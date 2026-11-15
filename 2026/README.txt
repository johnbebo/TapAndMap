TapAndMap 2026, created by John Bebo

The 2026 rebuild of TapAndMap: a Raspberry Pi that watches the traffic on a mirror (span)
port or network tap, geolocates every public address with MaxMind GeoLite2, and draws it
live on a Leaflet + OpenStreetMap map.  No Google Maps API key needed.

Step-by-step build instructions: http://TapAndMap.ninja
  (https://wuwablog.blogspot.com/2026/11/2026-tap-and-map-build-it-from-scratch.html)
The older 2025 build is at https://wuwablog.blogspot.com/2025/02/2025-tap-and-map.html

Where each file goes on the Pi:

  /var/www/TapAndMap.conf                        TapAndMap.conf  (edit HomeLat/HomeLong, TapAndMapIP, IgnoreIPs)
  /var/www/Sniff_Dev_Save_CSV.py                 sniffer: tap NIC -> /tmp/tempfile
  /var/www/TapAndMap_Web.py                      web exporter: /tmp/tempfile -> connections.json, logs/, history.json
  /var/www/Send_A_Random_UDP_Packet.py           test: sends one UDP packet to a random address
  /var/www/html/index.html                       live map page
  /var/www/html/history.html                     saved maps page
  /var/www/html/tapandmap.js                     map code (Leaflet)
  /var/www/html/tapandmap.css                    styles
  /var/www/html/leaflet/                         Leaflet 1.9.4 (download from https://leafletjs.com/download.html)
  /etc/systemd/system/tapandmap-sniffer.service  runs the sniffer at boot
  /etc/systemd/system/tapandmap-web.service      runs the web exporter at boot
  /etc/apache2/conf-available/tapandmap-nocache.conf   "a2enmod headers; a2enconf tapandmap-nocache"
  /etc/sysctl.d/90-tapandmap.conf                room for the kernel capture filter

Needs: apache2 python3-scapy python3-geoip2, plus MaxMind's geoipupdate and a free GeoLite2 account.
Tested on a Raspberry Pi 2 Model B running Raspberry Pi OS (bookworm).

Disclaimer: use at your own risk, and don't put it facing the Internet.
