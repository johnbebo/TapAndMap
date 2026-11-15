#!/usr/bin/python3
"""TapAndMap sniffer.

Sniffs the tap interface in promiscuous mode, geolocates the public end of each
IP packet, and appends one CSV line per packet to /tmp/tempfile:

    pkt,YYYY-mm-dd HH:MM:SS,src:port,dst:port,proto,lat,lon,city,country,zip

TapAndMap_Web.py (the tapandmap-web service) follows that file and feeds the map.
Runs as the tapandmap-sniffer service.  Settings come from /var/www/TapAndMap.conf:
IgnoreIPs, TapAndMapIP, and optionally SniffInterface={eth1}.

A kernel capture filter (BPF) built from IgnoreIPs drops non-IPv4 packets and
packets where BOTH ends are ignored, so Python never decodes them.  It also drops
the Pi's own clock-sync traffic (UDP port 123 to/from TapAndMapIP or any of the
Pi's interface addresses), so the Pi's NTP chatter doesn't land on the map.
The conf file is re-checked every few seconds (and the Pi's addresses every
minute); when IgnoreIPs, TapAndMapIP, the addresses or SniffInterface change, the
capture restarts with the new filter without resetting /tmp/tempfile (so the
live map keeps its data).  Each new filter is test-attached first; if the
kernel refuses it, the capture falls back to plain "ip" (Python still applies
the full ignore list, so the map stays correct) instead of crashing.
"""
import ipaddress
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime

import geoip2.database
import geoip2.errors
from scapy.all import AsyncSniffer
from scapy.arch.linux import attach_filter
from scapy.layers.inet import ICMP, IP, TCP, UDP

ETH_P_ALL = 0x0003

TEMPFILE = "/tmp/tempfile"
CONF = "/var/www/TapAndMap.conf"
DEFAULT_INTERFACE = "eth1"
CONF_CHECK_SECONDS = 3
# Newest of these wins; geoipupdate (cron) refreshes the /var/lib/GeoIP copy.
GEO_DBS = [
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/home/pi/TapAndMap/GeoDB/GeoLite2-City_20250207/GeoLite2-City.mmdb",
]
GEO_RECHECK_SECONDS = 600


def log(*args):
    print("TapAndMap sniffer:", *args, file=sys.stderr, flush=True)


def read_conf():
    vals = {}
    try:
        with open(CONF) as f:
            for line in f:
                m = re.match(r"\s*(\w+)\s*=\s*\{(.*)\}", line)
                if m:
                    vals[m.group(1)] = m.group(2).strip()
    except OSError as e:
        log("can't read", CONF, "-", e)
    return vals


class IgnoreList:
    """IgnoreIPs turned into octet-aligned networks.

    '10.' -> 10.0.0.0/8, '20.12.23' -> 20.12.23.0/24, '8.8.8.8' -> that host.
    The Python check and the kernel filter use the same networks, so they agree.
    """

    def __init__(self, text):
        networks = []
        prefixes, hosts, bad = [], set(), []
        for item in text.split():
            octets = item.strip(".").split(".")
            if not (1 <= len(octets) <= 4 and all(o.isdigit() and int(o) <= 255 for o in octets)):
                bad.append(item)
                continue
            octets = [str(int(o)) for o in octets]
            if len(octets) == 4:
                hosts.add(".".join(octets))
            else:
                prefixes.append(".".join(octets) + ".")
            networks.append(ipaddress.ip_network(
                ".".join(octets + ["0"] * (4 - len(octets))) + "/%d" % (8 * len(octets))))
        self.count = len(networks)
        # Merge overlapping/adjacent networks (e.g. 224.-239. -> 224.0.0.0/4) to keep the
        # kernel filter small; the kernel caps a socket filter's memory (net.core.optmem_max).
        self.nets = list(ipaddress.collapse_addresses(networks))
        self.prefixes = tuple(prefixes)
        self.hosts = frozenset(hosts)
        self.bad = bad

    def ignored(self, ip):
        return ip in self.hosts or ip.startswith(self.prefixes)

    def bpf(self):
        if not self.nets:
            return "ip"

        def side(direction):
            return " or ".join("%s host %s" % (direction, n.network_address) if n.prefixlen == 32
                               else "%s net %s" % (direction, n) for n in self.nets)

        return "ip and not ((%s) and (%s))" % (side("src"), side("dst"))


def own_addresses(conf):
    """The Pi's own IPv4 addresses: TapAndMapIP from the conf plus every interface address."""
    addrs = set()
    for item in conf.get("TapAndMapIP", "").split():
        try:
            addrs.add(str(ipaddress.IPv4Address(item)))
        except ValueError:
            log("ignoring TapAndMapIP value that isn't an IPv4 address:", item)
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, timeout=5).stdout
        addrs.update(m for m in re.findall(r"\binet (\d+\.\d+\.\d+\.\d+)/", out) if not m.startswith("127."))
    except (OSError, subprocess.SubprocessError) as e:
        log("couldn't list interface addresses:", e)
    return frozenset(addrs)


class Geo:
    """GeoIP reader opened once, reopened when a newer database appears."""

    def __init__(self):
        self.reader = None
        self.path = None
        self.mtime = None
        self.checked = 0
        self.refresh(force=True)

    @staticmethod
    def newest():
        found = [(os.path.getmtime(p), p) for p in GEO_DBS if os.path.exists(p)]
        return max(found) if found else (None, None)

    def refresh(self, force=False):
        now = time.monotonic()
        if not force and now - self.checked < GEO_RECHECK_SECONDS:
            return
        self.checked = now
        mtime, path = self.newest()
        if path is None:
            if force:
                sys.exit("TapAndMap sniffer: no GeoLite2-City.mmdb found in " + ", ".join(GEO_DBS))
            return
        if (path, mtime) == (self.path, self.mtime):
            return
        old = self.reader
        self.reader = geoip2.database.Reader(path)
        self.path, self.mtime = path, mtime
        if old:
            old.close()
        log("using GeoIP database", path, "dated", datetime.fromtimestamp(mtime).strftime("%Y-%m-%d"))

    def lookup(self, ip):
        self.refresh()
        try:
            return self.reader.city(ip)
        except (geoip2.errors.AddressNotFoundError, ValueError):
            return None


def kernel_accepts(bpf, interface):
    """Attach the filter to a throwaway socket, exactly as the capture will.

    Compiling isn't enough: the kernel can still refuse a large filter at attach
    time (ENOMEM from net.core.optmem_max), which would kill the capture thread.
    """
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    try:
        attach_filter(s, bpf, interface)
        return None
    except Exception as e:
        return str(e) or e.__class__.__name__
    finally:
        s.close()


def clean(value):
    """GeoIP fields can be None; commas would shift the CSV columns."""
    return "UNK" if value is None else str(value).replace(",", " ")


class Sniffer:
    def __init__(self):
        self.geo = Geo()
        self.counter = 0
        self.capture = None
        self.settings = None        # (interface, IgnoreIPs text, own addresses) the capture is using
        self.ignore = IgnoreList("")
        self.own = frozenset()      # the Pi's own addresses; their NTP (UDP 123) is dropped
        self.conf_mtime = None
        self.addr_checked = 0
        if os.path.exists(TEMPFILE):
            os.remove(TEMPFILE)     # a new file = a new session for the web service
        self.out = open(TEMPFILE, "a", buffering=1)  # line-buffered: each line lands whole

    def handle(self, packet):
        if not packet.haslayer(IP):
            return
        src, dst = packet[IP].src, packet[IP].dst
        ignore = self.ignore

        # The Pi's own clock sync (also dropped by the kernel filter; this covers the fallback filter).
        if packet.haslayer(UDP) and (src in self.own or dst in self.own) \
                and 123 in (packet[UDP].sport, packet[UDP].dport):
            return

        # Same rule as before: geolocate the source if it's public, otherwise the destination.
        remote = src if not ignore.ignored(src) else dst if not ignore.ignored(dst) else None
        if remote is None:
            return
        # No GeoIP record (unassigned or reserved space): still log it, with no location,
        # so it shows in the list as "Unknown location" instead of vanishing.
        geo = self.geo.lookup(remote)

        if packet.haslayer(TCP):
            proto, sport, dport = "TCP", packet[TCP].sport, packet[TCP].dport
        elif packet.haslayer(UDP):
            proto, sport, dport = "UDP", packet[UDP].sport, packet[UDP].dport
        elif packet.haslayer(ICMP):
            proto, sport, dport = "ICMP", packet[ICMP].type, packet[ICMP].type
        else:
            proto, sport, dport = "NA", "NA", "NA"

        self.counter += 1
        self.out.write(",".join([
            str(self.counter),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "%s:%s" % (src, sport),
            "%s:%s" % (dst, dport),
            proto,
            str(geo.location.latitude) if geo else "None",
            str(geo.location.longitude) if geo else "None",
            clean(geo.city.name if geo else None),
            clean(geo.country.name if geo else None),
            clean(geo.postal.code if geo else None),
        ]) + "\n")

    def apply_conf(self):
        """(Re)start the capture if the interface, IgnoreIPs or the Pi's addresses changed.

        Returns False on a bad first start."""
        conf = read_conf()
        interface = conf.get("SniffInterface", "") or DEFAULT_INTERFACE
        own = own_addresses(conf)
        self.addr_checked = time.monotonic()
        settings = (interface, conf.get("IgnoreIPs", ""), own)
        if settings == self.settings:
            return True

        ignore = IgnoreList(settings[1])
        if ignore.bad:
            log("skipping IgnoreIPs entries that aren't IPv4 prefixes:", " ".join(ignore.bad))
        # Python always applies the full ignore list, so the kernel filter is only an
        # optimisation: if the full one is refused, plain "ip" still gives a correct map.
        bpf, note = ignore.bpf(), "full filter"
        if own:
            bpf += " and not (udp port 123 and (%s))" % " or ".join("host " + a for a in sorted(own))
        error = kernel_accepts(bpf, interface)
        if error:
            log("kernel refused the full capture filter (%s); falling back to plain 'ip' "
                "(map stays correct, but uses more CPU)" % error)
            bpf, note = "ip", "fallback filter"
            error = kernel_accepts(bpf, interface)
        if error:
            log("can't capture on %s (%s); %s" % (
                interface, error, "keeping the previous capture" if self.capture else "giving up"))
            if self.capture:
                self.settings = settings        # don't retry the same bad conf every few seconds
            return self.capture is not None

        if self.capture:
            self.capture.stop()
        self.ignore = ignore
        self.own = own
        self.capture = AsyncSniffer(iface=interface, prn=self.handle, store=False, filter=bpf, promisc=True)
        self.capture.start()
        log("%s capture on %s, ignoring %d prefixes merged into %d networks and NTP of %s (%s)" % (
            "restarted" if self.settings else "started", interface, ignore.count, len(ignore.nets),
            ", ".join(sorted(own)) or "no own address found", note))
        self.settings = settings
        return True

    def run(self):
        if not self.apply_conf():
            sys.exit(1)
        while True:
            time.sleep(CONF_CHECK_SECONDS)
            try:
                mtime = os.path.getmtime(CONF)
            except OSError:
                mtime = None
            if mtime != self.conf_mtime or time.monotonic() - self.addr_checked > 60:
                self.conf_mtime = mtime
                self.apply_conf()           # no-op unless something actually changed
            thread = getattr(self.capture, "thread", None)
            if thread is not None and not thread.is_alive():
                sys.exit("TapAndMap sniffer: capture stopped unexpectedly (interface down?); exiting so systemd restarts it")


if __name__ == "__main__":
    Sniffer().run()
