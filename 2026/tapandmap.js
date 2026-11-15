/* Tap And Map - shared map code for index.html (live) and history.html (saved logs).
 * The pages are static; all data comes from connections.json / history.json / logs/*.txt,
 * written by /var/www/TapAndMap_Web.py.  Everything is fetched with cache: "no-store".
 * Map: Leaflet (served from /leaflet/ on the Pi) with OpenStreetMap tiles.
 */
"use strict";
(function () {
  const COLORS = { TCP: "#d93025", UDP: "#1a73e8", ICMP: "#188038" };
  const colorFor = (p) => COLORS[p] || COLORS.TCP;
  const $ = (id) => document.getElementById(id);

  let map = null, home = null, zoomPref = 3, session = null;
  const drawn = new Map();          // "lat,lon" -> { marker, line, d }
  let dests = [];

  function setStatus(text, bad) {
    const s = $("status");
    s.textContent = text;
    s.classList.toggle("bad", !!bad);
  }

  function mapError(text) {
    const m = $("map");
    m.textContent = text;
    m.classList.add("map-error");
  }

  async function getJSON(url) {
    const r = await fetch(url, { cache: "no-store" });
    if (!r.ok) throw new Error(url + ": HTTP " + r.status);
    return r.json();
  }

  // Mirror of parse_line() in TapAndMap_Web.py, for saved logs.
  function parseLine(line) {
    const p = line.replace(/\r$/, "").split(",");
    if (p.length < 10) return null;
    const split = (s) => { const i = s.lastIndexOf(":"); return i < 0 ? [s, ""] : [s.slice(0, i), s.slice(i + 1)]; };
    const [src, sport] = split(p[2]), [dst, dport] = split(p[3]);
    let lat = parseFloat(p[5]), lon = parseFloat(p[6]);
    if (!isFinite(lat) || !isFinite(lon)) lat = lon = null;
    return { pkt: p[0], time: p[1], src, sport, dst, dport, proto: p[4], lat, lon,
             city: p.slice(7, -2).join(",").trim(), country: p[p.length - 2].trim(), zip: p[p.length - 1].trim() };
  }

  // Rough check for local addresses, to count the public end of a saved packet.
  function isPrivate(ip) {
    const o = ip.split(".").map(Number);
    return o[0] === 10 || o[0] === 127 || (o[0] === 192 && o[1] === 168) || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) ||
           (o[0] === 169 && o[1] === 254) || o[0] >= 224;
  }

  /* ---------------- map drawing ---------------- */

  function clearMap() {
    for (const o of drawn.values()) { o.marker.remove(); o.line.remove(); }
    drawn.clear();
    if (map) map.closePopup();
  }

  // Dot radius (px) grows with the packet count (logarithmically), so busy locations stand out:
  // 1 packet = 5, 64 = 11.6, 1,000 = 16, 30,000 = 21, 1,000,000 = 27, capped at 28.
  const radiusFor = (d) => Math.min(5 + Math.log2(d.count || 1) * 1.1, 28);
  const dotStyle = (d) => ({ radius: radiusFor(d), fillColor: colorFor(d.proto), fillOpacity: 0.8,
                             color: "#fff", weight: 1, opacity: 1 });

  // Great-circle path from home to a location (what Google's "geodesic" lines did), with the
  // longitudes unwrapped so a line over the Pacific doesn't jump across the whole map.
  // The dot goes at the end of the path, i.e. on the world copy nearest home.
  function greatCircle(a, b) {
    const rad = Math.PI / 180, deg = 180 / Math.PI;
    const toVec = (p) => [Math.cos(p.lat * rad) * Math.cos(p.lng * rad), Math.cos(p.lat * rad) * Math.sin(p.lng * rad), Math.sin(p.lat * rad)];
    const va = toVec(a), vb = toVec(b);
    const dot = Math.max(-1, Math.min(1, va[0] * vb[0] + va[1] * vb[1] + va[2] * vb[2]));
    const omega = Math.acos(dot);
    const n = Math.max(1, Math.ceil(omega * deg / 2));          // a point every ~2 degrees
    const pts = [];
    let prevLng = a.lng;
    for (let i = 0; i <= n; i++) {
      const t = i / n;
      let v;
      if (omega < 1e-9) v = va;
      else {
        const s = Math.sin(omega), ka = Math.sin((1 - t) * omega) / s, kb = Math.sin(t * omega) / s;
        v = [ka * va[0] + kb * vb[0], ka * va[1] + kb * vb[1], ka * va[2] + kb * vb[2]];
      }
      const lat = Math.atan2(v[2], Math.hypot(v[0], v[1])) * deg;
      let lng = i === 0 ? a.lng : Math.atan2(v[1], v[0]) * deg;
      lng += 360 * Math.round((prevLng - lng) / 360);           // keep it continuous
      prevLng = lng;
      pts.push([lat, lng]);
    }
    return pts;
  }

  // Smaller (quieter) dots draw on top of bigger ones, so a big dot can't hide them.
  // SVG has no z-index, so re-stack (biggest first) whenever a dot is added or resized.
  function restack() {
    const entries = [...drawn.values()].sort((x, y) => y.marker.getRadius() - x.marker.getRadius());
    for (const e of entries) e.marker.bringToFront();
  }

  function place(d) { return [d.city, d.country].filter((x) => x && x !== "UNK" && x !== "None").join(", ") || "Unknown location"; }

  function infoContent(d) {
    const div = document.createElement("div");
    div.className = "iw";
    const add = (tag, text) => { const e = document.createElement(tag); e.textContent = text; div.appendChild(e); };
    add("strong", place(d));
    add("p", `Latest: ${d.src}:${d.sport} → ${d.dst}:${d.dport} (${d.proto})`);
    const protos = Object.entries(d.protos || {}).sort((a, b) => b[1] - a[1]).map(([p, n]) => `${p} ${n}`).join(", ");
    add("p", `Seen ${d.count} time${d.count === 1 ? "" : "s"}${protos ? " (" + protos + ")" : ""}` +
             (d.hosts > 1 ? ` · ${d.hosts} different addresses` : ""));
    add("p", `First ${d.first} · last ${d.last}`);
    add("p", `${d.lat}, ${d.lon}${d.zip && d.zip !== "None" && d.zip !== "UNK" ? " · " + d.zip : ""}`);
    return div;
  }

  function draw() {
    if (!map || !home) return;
    let restackNeeded = false;
    for (const d of dests) {
      const old = drawn.get(d.key);
      if (old) {
        // Colour follows the location's latest packet, like the list beside the map.
        if (old.d.proto !== d.proto) {
          old.line.setStyle({ color: colorFor(d.proto) });
          old.marker.setStyle({ fillColor: colorFor(d.proto) });
        }
        const r = radiusFor(d);
        if (r !== old.marker.getRadius()) { old.marker.setRadius(r); restackNeeded = true; }
        old.d = d;
        continue;
      }
      const path = greatCircle(home, { lat: d.lat, lng: d.lon });
      const line = L.polyline(path, { pane: "lines", color: colorFor(d.proto), opacity: 0.8, weight: 2,
                                      interactive: false }).addTo(map);
      const marker = L.circleMarker(path[path.length - 1], dotStyle(d)).addTo(map);
      const entry = { marker, line, d };
      marker.bindTooltip(() => place(entry.d));
      marker.bindPopup(() => infoContent(entry.d));
      drawn.set(d.key, entry);
      restackNeeded = true;
    }
    if (restackNeeded) restack();
  }

  function focus(key) {
    const e = drawn.get(key);
    if (!e) return;
    map.panTo(e.marker.getLatLng());
    e.marker.openPopup();
  }

  function setHome(h, zoom) {
    if (!h) return;
    const nh = { lat: h[0], lng: h[1] };
    if (zoom) zoomPref = zoom;
    if (home && home.lat === nh.lat && home.lng === nh.lng) return;
    const first = !home;
    home = nh;
    clearMap();                                  // lines start at home, so redraw them
    if (map && first) map.setView(home, zoomPref);
  }

  function initMap() {
    if (typeof L === "undefined") {
      mapError("Couldn't load the map library (leaflet/leaflet.js). The connection list still works.");
      return;
    }
    map = L.map($("map"), { center: home || [20, 0], zoom: zoomPref, minZoom: 2, worldCopyJump: false });
    // Lines get their own layer under the dots, so a dot is always clickable.
    map.createPane("lines").style.zIndex = 350;
    let tileErrors = 0;
    L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 19,
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
    }).on("tileerror", () => {
      if (++tileErrors === 4) map.attributionControl.addAttribution(
        '<span style="color:#a00">Map tiles not loading (is this browser online?)</span>');
    }).addTo(map);
    if (document.body.dataset.mode !== "history") addMapButtons();
    draw();
  }

  /* ---------------- side panel ---------------- */

  function renderList(rows, fontSize) {
    const ul = $("list");
    ul.style.fontSize = (fontSize || 75) + "%";
    const frag = document.createDocumentFragment();
    for (const c of rows) {
      const li = document.createElement("li");
      li.style.color = colorFor(c.proto);
      li.textContent = `${c.src}:${c.sport} → ${c.dst}:${c.dport} ${place(c)}`;
      li.title = `${c.time} · packet ${c.pkt}`;
      if (c.lat !== null) {
        li.classList.add("located");
        li.addEventListener("click", () => focus(c.lat + "," + c.lon));
      }
      frag.appendChild(li);
    }
    ul.replaceChildren(frag);
  }

  /* ---------------- live page ---------------- */

  // "Clear Map" is a view filter in this browser only: it remembers what had been seen
  // (each location's count and the last packet number) and hides it.  A location comes
  // back when it gets new packets.  Remembered across reloads; reset when the sniffer restarts.
  const CLEAR_KEY = "tapandmap.cleared";
  let refreshMs = 1000, lastData = null, cleared = null;   // cleared = { session, pkt, counts, at }
  try { cleared = JSON.parse(localStorage.getItem(CLEAR_KEY)); } catch (e) { cleared = null; }

  function saveCleared() {
    try {
      if (cleared) localStorage.setItem(CLEAR_KEY, JSON.stringify(cleared));
      else localStorage.removeItem(CLEAR_KEY);
    } catch (e) { /* storage blocked: clearing still works until reload */ }
  }

  function showLive() {
    const data = lastData;
    if (!data) return;
    if (cleared && cleared.session !== data.session) { cleared = null; saveCleared(); }
    const c = cleared;
    dests = c ? data.destinations.filter((d) => !(d.key in c.counts) || d.count > c.counts[d.key]) : data.destinations;
    draw();
    const recent = c ? data.recent.filter((r) => Number(r.pkt) > c.pkt) : data.recent;
    renderList(recent.slice().reverse(), data.fontSize);
    const n = dests.length, where = `${n} location${n === 1 ? "" : "s"}`;
    setStatus(`Live · ${where}${c ? " since cleared at " + c.at : ""} · updated ${new Date().toLocaleTimeString()}`);
    const showAllBtn = $("show-all-btn");
    if (showAllBtn) showAllBtn.hidden = !c;
  }

  function clearNow() {
    if (!lastData) return;
    const counts = {};
    for (const d of lastData.destinations) counts[d.key] = d.count;
    const pkt = lastData.recent.reduce((m, r) => Math.max(m, Number(r.pkt) || 0), 0);
    cleared = { session: lastData.session, pkt, counts, at: new Date().toLocaleTimeString() };
    saveCleared();
    clearMap();
    showLive();
  }

  function showAll() {
    cleared = null;
    saveCleared();
    showLive();
  }

  function addMapButtons() {
    const box = document.createElement("div");
    box.className = "map-ctl";
    const make = (id, label, tip, onClick) => {
      const b = document.createElement("button");
      b.type = "button"; b.id = id; b.textContent = label; b.title = tip;
      b.addEventListener("click", onClick);
      box.appendChild(b);
      return b;
    };
    make("clear-btn", "Clear Map", "Hide everything seen so far; only new traffic will appear", clearNow);
    make("show-all-btn", "Show all", "Bring back everything hidden by Clear Map", showAll).hidden = !cleared;
    // Leaflet has no top-centre control slot, so float the box over the map (see tapandmap.css).
    L.DomEvent.disableClickPropagation(box);
    L.DomEvent.disableScrollPropagation(box);
    map.getContainer().appendChild(box);
  }

  async function poll() {
    try {
      const data = await getJSON("connections.json");
      if (data.session !== session) { session = data.session; clearMap(); }
      refreshMs = Math.max(500, data.refreshMs || 1000);
      setHome(data.home, data.zoom);
      lastData = data;
      showLive();
    } catch (e) {
      setStatus("Can't load connections.json. Is the TapAndMap-web service running? Retrying…", true);
      refreshMs = 3000;
    } finally {
      setTimeout(poll, refreshMs);
    }
  }

  /* ---------------- history page ---------------- */

  const HISTORY_LIST_MAX = 1000;
  async function showLog(name) {
    setStatus("Loading " + name + "…");
    try {
      const r = await fetch("logs/" + encodeURIComponent(name), { cache: "no-store" });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const rows = [], byKey = new Map(), remotes = new Map();
      for (const line of (await r.text()).split("\n")) {
        const c = parseLine(line);
        if (!c) continue;
        rows.push(c);
        if (c.lat === null) continue;
        // Same rules as TapAndMap_Web.py: the marker follows the latest packet at this location.
        const key = c.lat + "," + c.lon;
        let d = byKey.get(key);
        if (!d) { d = { key, count: 0, first: c.time, protos: {}, hosts: 0 }; byKey.set(key, d); remotes.set(key, new Set()); }
        // ICMP error replies (type in the port column) are counted but don't take over the colour.
        const icmpError = c.proto === "ICMP" && ["3", "4", "5", "11", "12"].includes(c.sport);
        if (!(icmpError && d.count)) Object.assign(d, c);
        d.count++;
        d.last = c.time;
        d.protos[c.proto] = (d.protos[c.proto] || 0) + 1;
        const seen = remotes.get(key);
        seen.add(isPrivate(c.src) ? c.dst : c.src);
        d.hosts = seen.size;
      }
      clearMap();
      dests = [...byKey.values()];
      draw();
      renderList(rows.slice(-HISTORY_LIST_MAX).reverse(), 75);
      history.replaceState(null, "", "?log=" + encodeURIComponent(name));
      setStatus(`${name} · ${rows.length} packet${rows.length === 1 ? "" : "s"} · ${dests.length} location${dests.length === 1 ? "" : "s"}` +
                (rows.length > HISTORY_LIST_MAX ? ` (list shows last ${HISTORY_LIST_MAX})` : ""));
    } catch (e) {
      setStatus("Couldn't load " + name + ": " + e.message, true);
    }
  }

  async function startHistory() {
    try { const cfg = await getJSON("connections.json"); setHome(cfg.home, cfg.zoom); } catch (e) { /* map still works */ }
    let logs = [];
    try { logs = (await getJSON("history.json")).logs; } catch (e) { /* none yet */ }
    const sel = $("logs");
    const label = (name) => {
      const base = name.replace(/_Connections(_\d+)?\.txt$/, " $1").replace(/_/g, " ").trim();
      const m = /^(\d{4})-(\d\d)-(\d\d)$/.exec(base);           // daily log: add the weekday
      return m ? new Date(+m[1], m[2] - 1, +m[3]).toLocaleDateString(undefined, { weekday: "short" }) + " " + base : base;
    };
    for (const name of logs) sel.add(new Option(label(name), name));
    if (!logs.length) { setStatus("No saved logs yet. They appear after the first packets are captured."); return; }
    sel.addEventListener("change", () => showLog(sel.value));
    const want = new URLSearchParams(location.search).get("log");
    sel.value = logs.includes(want) ? want : logs[0];
    showLog(sel.value);
  }

  document.addEventListener("DOMContentLoaded", () => {
    initMap();
    if (document.body.dataset.mode === "history") startHistory(); else poll();
  });
})();
