#!/usr/bin/python3
"""TapAndMap web exporter.

Replaces Read_CSV_Write_Html.py.  Instead of regenerating HTML, this runs as a
service, follows the sniffer's /tmp/tempfile as it grows, and publishes:

  /var/www/html/connections.json   live data for index.html (rewritten atomically)
  /var/www/html/logs/*.txt         the raw CSV split every LogRun minutes
  /var/www/html/history.json       list of those log files, for history.html

The web pages (index.html, history.html, tapandmap.js) are static and never
rewritten, so the browser can't catch a half-written page.
"""
import ipaddress
import json
import os
import re
import time
from collections import deque
from datetime import datetime

TEMPFILE = "/tmp/tempfile"
CONF = "/var/www/TapAndMap.conf"
WEBROOT = "/var/www/html"
LOGDIR = os.path.join(WEBROOT, "logs")
DATA_FILE = os.path.join(WEBROOT, "connections.json")
HISTORY_FILE = os.path.join(WEBROOT, "history.json")
POLL_SECONDS = 1.0


def read_conf():
    """Return {Name: value} for every Name={value} line in TapAndMap.conf."""
    vals = {}
    try:
        with open(CONF) as f:
            for line in f:
                m = re.match(r"\s*(\w+)\s*=\s*\{(.*)\}", line)
                if m:
                    vals[m.group(1)] = m.group(2).strip()
    except OSError:
        pass
    return vals


def conf_num(vals, key, default, cast=float):
    try:
        return cast(vals[key])
    except (KeyError, ValueError):
        return default


def atomic_write(path, text):
    """Write to a temp file then rename, so readers only ever see a complete file."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def parse_line(line):
    """Parse one sniffer CSV line.  Returns a dict, or None if it isn't a data line.

    Format: pkt,time,src:port,dst:port,proto,lat,lon,city,country,zip
    A city containing a comma is rejoined instead of dropping the line.
    """
    p = line.rstrip("\r\n").split(",")
    if len(p) < 10:
        return None
    src, _, sport = p[2].rpartition(":")
    dst, _, dport = p[3].rpartition(":")
    try:
        lat, lon = float(p[5]), float(p[6])
    except ValueError:
        lat = lon = None
    return {
        "pkt": p[0], "time": p[1],
        "src": src, "sport": sport, "dst": dst, "dport": dport,
        "proto": p[4], "lat": lat, "lon": lon,
        "city": ",".join(p[7:-2]).strip(), "country": p[-2].strip(), "zip": p[-1].strip(),
    }


MAX_HOSTS_PER_LOCATION = 5000
ICMP_ERROR_TYPES = {"3", "4", "5", "11", "12"}   # unreachable, quench, redirect, time exceeded, param problem


def is_icmp_error(c):
    """The sniffer writes the ICMP type in the port column."""
    return c["proto"] == "ICMP" and c["sport"] in ICMP_ERROR_TYPES


def remote_end(src, dst):
    """The public address of a packet (the one the sniffer geolocated)."""
    try:
        return src if ipaddress.ip_address(src).is_global else dst
    except ValueError:
        return src


def bucket_name(timestamp, minutes):
    """Round a 'YYYY-mm-dd HH:MM:SS' timestamp down to its LogRun bucket."""
    try:
        t = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    minutes = max(1, min(int(minutes), 1440))
    if minutes == 1440:
        return t.strftime("%Y-%m-%d")                 # daily logs: just the date
    since_midnight = (t.hour * 60 + t.minute) // minutes * minutes
    return "%s_%02d-%02d" % (t.strftime("%Y-%m-%d"), since_midnight // 60, since_midnight % 60)


class Session:
    """Everything derived from one run of the sniffer (one /tmp/tempfile)."""

    def __init__(self, session_id, recent_len):
        self.id = session_id
        # Inode numbers get reused, so the browser gets a token that is unique per reset.
        self.token = "%s-%d" % (session_id, time.time() * 1000)
        self.offset = 0
        self.partial = b""
        self.destinations = {}      # "lat,lon" -> aggregated info
        self.remotes = {}           # "lat,lon" -> set of public addresses seen there
        self.recent = deque(maxlen=recent_len)
        self.buckets = {}           # bucket -> list of raw lines from this session
        self.earlier = {}           # bucket -> lines already in its log from earlier sniffer runs
        self.dirty_buckets = set()
        self.log_minutes = None
        self.changed = True

    def add(self, raw, log_minutes):
        c = parse_line(raw)
        if c is None:
            return
        self.changed = True
        self.recent.append(c)

        b = bucket_name(c["time"], log_minutes)
        if b:
            self.buckets.setdefault(b, []).append(raw)
            self.dirty_buckets.add(b)

        if c["lat"] is None:
            return
        # One map marker per location.  Several addresses can share a location (GeoIP puts
        # every "country only" address at the same spot), so the marker follows the LATEST
        # packet (protocol, addresses) and keeps per-protocol and per-address tallies.
        key = "%s,%s" % (c["lat"], c["lon"])
        d = self.destinations.get(key)
        if d is None:
            d = dict(c, key=key, count=0, first=c["time"], protos={}, hosts=0)
            self.destinations[key] = d
            self.remotes[key] = set()
        # Latest packet's proto / src / dst / ports.  ICMP error replies ("port unreachable",
        # "time exceeded", ...) answer other traffic, so they're counted but don't take over.
        if not (is_icmp_error(c) and d["count"]):
            d.update(c)
        d["count"] += 1
        d["last"] = c["time"]
        d["protos"][c["proto"]] = d["protos"].get(c["proto"], 0) + 1
        seen = self.remotes[key]
        if len(seen) < MAX_HOSTS_PER_LOCATION:
            seen.add(remote_end(c["src"], c["dst"]))
            d["hosts"] = len(seen)

    def log_lines(self, bucket, path):
        """All lines for a bucket's log: earlier sniffer runs' lines first, then this session's.

        One file per bucket even if the sniffer restarts mid-day.  The first time we
        touch a bucket we read its existing log and keep every line that isn't ours
        (ours are already in self.buckets, since we re-read /tmp/tempfile from the
        start).  Lines carry a packet number and a timestamp, so another run's line
        can't be mistaken for ours.
        """
        if bucket not in self.earlier:
            ours = set(self.buckets[bucket])
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    existing = [l.rstrip("\n") for l in f if l.strip()]
            except FileNotFoundError:
                existing = []
            self.earlier[bucket] = [l for l in existing if l not in ours]
        return self.earlier[bucket] + self.buckets[bucket]


def write_logs(sess):
    if not sess.dirty_buckets:
        return
    os.makedirs(LOGDIR, exist_ok=True)
    for b in sorted(sess.dirty_buckets):
        path = os.path.join(LOGDIR, "%s_Connections.txt" % b)
        atomic_write(path, "\n".join(sess.log_lines(b, path)) + "\n")
    sess.dirty_buckets.clear()
    logs = sorted((f for f in os.listdir(LOGDIR) if f.endswith(".txt")), reverse=True)
    atomic_write(HISTORY_FILE, json.dumps({"logs": logs}))


def write_data(sess, vals):
    home = None
    try:
        home = [float(vals["HomeLat"]), float(vals["HomeLong"])]
    except (KeyError, ValueError):
        pass
    data = {
        "session": sess.token,
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "home": home,
        "zoom": conf_num(vals, "ZoomLevel", 3, int),
        "fontSize": conf_num(vals, "FontSize", 75, int),
        "packetLines": conf_num(vals, "PacketLine", 46, int),
        "refreshMs": conf_num(vals, "RefreshRate", 1000, int),
        "destinations": list(sess.destinations.values()),
        "recent": list(sess.recent),
    }
    atomic_write(DATA_FILE, json.dumps(data, separators=(",", ":")))
    sess.changed = False


def main():
    sess = None
    last_conf = None
    while True:
        vals = read_conf()
        recent_len = max(1, conf_num(vals, "PacketLine", 46, int))
        log_minutes = conf_num(vals, "LogRun", 60, int)

        try:
            st = os.stat(TEMPFILE)
            session_id = str(st.st_ino)     # sniffer deletes and recreates the file on start
        except FileNotFoundError:
            st, session_id = None, "none"

        # New sniffer run (file recreated or truncated) -> start over.  Also rebuild from
        # the start of /tmp/tempfile if PacketLine or LogRun changed, so every bucket uses
        # the new log length (existing logs are kept, see Session.log_lines).
        if (sess is None or sess.id != session_id or (st and st.st_size < sess.offset)
                or sess.recent.maxlen != recent_len or sess.log_minutes != log_minutes):
            same_run = sess is not None and sess.id == session_id and not (st and st.st_size < sess.offset)
            old_token = sess.token if same_run else None
            sess = Session(session_id, recent_len)
            sess.log_minutes = log_minutes
            if old_token:
                sess.token = old_token      # same sniffer run: don't make browsers reset the map

        if st and st.st_size > sess.offset:
            with open(TEMPFILE, "rb") as f:
                f.seek(sess.offset)
                chunk = f.read()
                sess.offset = f.tell()
            lines = (sess.partial + chunk).split(b"\n")
            sess.partial = lines.pop()      # keep any half-written last line for next time
            for raw in lines:
                sess.add(raw.decode("utf-8", "replace").rstrip("\r"), log_minutes)

        if vals != last_conf:
            sess.changed = True
            last_conf = vals

        try:
            write_logs(sess)
            if sess.changed:
                write_data(sess, vals)
        except OSError as e:
            print("TapAndMap_Web: write failed:", e, flush=True)

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
