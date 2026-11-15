TapAndMap Version 1.3, created by John Bebo

For installation instructions for the files in this folder (the 2025 version), go to
https://wuwablog.blogspot.com/2025/02/2025-tap-and-map.html

NEW: the 2026 version (Leaflet + OpenStreetMap, no Google Maps key, runs as systemd services) is in the 2026 folder.
See 2026/README.txt, and http://TapAndMap.ninja for the 2026 build instructions.

Feel free to donate a few BitCoin to 1Pq1pwxauSj1zQQLLQA4Suc9azVfFYU2dX

TapAndMap is designed to run on a Raspberry Pi (2 or 3), with the on-board Ethernet used to manage and browse to it.
It will sniff from either two USB Ethernet dongles (acting as a bridge), or a single USB Ethernet Dongle (connected to a spanning port, network tap, or hub).
It will then plot the public points it sees on Google Maps, as well as displaying textual data on the packets.

Disclaimer:  I am not a web programmer, so use at your own risk.  I wouldn't put it facing the Internet, as it is probably vulnerable. 
Feel free to email me at TapAndMap at johnbebo dot com if you have any recommendations or especially fixes. 
