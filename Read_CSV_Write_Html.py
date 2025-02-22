#!/usr/bin/python3

# This script will continually read in the file made by the "Sniff_Dev_Save_CSV.py" script, and write html pages to be served up by a web-server

import os
import time

HomePoint = ""
ConnectionsSeen = []
# Read in file of connections, and store them in memory to be written later by the html writer.  Make one if it's gone so as not to error out
f = open("/tmp/tempfile", 'a')
f.close()
f = open("/tmp/tempfile", 'r')
AllConnectionsSeen = f.readlines()
for item in AllConnectionsSeen:
    #print(item)
    getcoords = str(item.split(",")[5:6]) + "," + str(item.split(",")[6:7])
    getcoords = getcoords.replace("[", "")
    getcoords = getcoords.replace("]", "")
    getcoords = getcoords.replace("'", "")
    #print("Coords are: " + getcoords + "\n")
    if getcoords not in str(ConnectionsSeen) and "None" not in getcoords:   # To save markers, only add ones you've not already seen
        ConnectionsSeen.append(item)

#print(ConnectionsSeen)
# Read in TapAndMap.conf and get necessary info
Config_F = open("/var/www/TapAndMap.conf", 'r')
HomeLat = ""
HomeLong = ""
for line in Config_F:
    if "HomeLat" in line:
        HomeLat = str(line)
        HomeLat = HomeLat[HomeLat.find('{')+1:HomeLat.rfind('}')]
    elif "HomeLong" in line:
        HomeLong = line
        HomeLong = HomeLong[HomeLong.find('{')+1:HomeLong.rfind('}')]
    HomePoint = str(HomeLat + " " + str(HomeLong))
Config_F.close()
#print("HomePoint is: " + HomePoint)

# Now, to write the necessary html file for TapAndMap

writeIndexFile = open("/var/www/html/index.html", 'w')
writeIndexFile.write("<!DOCTYPE html> \n")
writeIndexFile.write('<meta http-equiv="content-type" content="text/html; charset=UTF-8"> \n')
writeIndexFile.write("<!-- ***********************      Tap And Map   ********************************************** \n")
writeIndexFile.write("**     a hardware platform to Tap an etherenet line, and Map those packets on Google Maps   ** \n")
writeIndexFile.write("********************************************************************************************** \n")
writeIndexFile.write(" \n")
writeIndexFile.write("This app is currently built for the Raspberry Pi V2 b. \n")
writeIndexFile.write("It is designed to 'tap' two USB NICs, pull the connection information from those NICs  \n")
writeIndexFile.write("custom written python sniffer code that finds public IP addresses and their geolocation information.  \n")
writeIndexFile.write("The Pi serves up a webserver that will dynamically 'map' this info on GoogleMaps \n")
writeIndexFile.write("(RJ45 jack is the webserver, with an IP of 192.168.1.199/24, gw of 1.1 by default) \n")
writeIndexFile.write(" \n")
writeIndexFile.write("Tap takes to/from IP, protocol,and to/from port and finds the location of the public IPs \n")
writeIndexFile.write("and saves this information in a log called ConnectionsSeen.txt. \n")
writeIndexFile.write(" \n")
writeIndexFile.write("Map then dynamically maps those lines, drawing lines and circles in an animated fashon  \n")
writeIndexFile.write("The circles are clickable to present connection information \n")
writeIndexFile.write("There is also an information windown on the right, for those who like text better than maps \n")
writeIndexFile.write("Left To Do: \n")
writeIndexFile.write("- make the line, circle, listner functions, vs inline calls \n")
writeIndexFile.write("- Notice that below everything is part of the 'initialize' function.  Need to make DrawLine,  \n")
writeIndexFile.write("  PlaceCircle, and PlaceListner all their own functions outside of this function \n")
writeIndexFile.write("- read in and plot connections from the log file (vs in line below) \n")
writeIndexFile.write("- change circle size depending on volume of traffic \n")
writeIndexFile.write("- expire connections after a user clicks on a 'Clear Connections' button. \n")
writeIndexFile.write("- allow for users to click on info in right-hand pane, and highlight that infowindow on map \n")
writeIndexFile.write("- have connections scroll down the information window on the right \n")
writeIndexFile.write("- Copyrite this code, Copyright/Trademark? the name (TapNMap)  \n")
writeIndexFile.write("********************************************************************************************--> \n")
writeIndexFile.write("<title> Tap And Map </title> \n")
writeIndexFile.write('<style type="text/css">.gm-style .gm-style-mtc label,.gm-style .gm-style-mtc div{font-weight:400}</style> \n')
writeIndexFile.write('<style type="text/css">.gm-style .gm-style-cc span,.gm-style .gm-style-cc a,.gm-style .gm-style-mtc div{font-size:10px}</style> \n')
writeIndexFile.write('<style type="text/css">@media print {  .gm-style .gmnoprint, .gmnoprint {    display:none  }}@media screen {  .gm-style .gmnoscreen, .gmnoscreen {    display:none  }}</style> \n')
writeIndexFile.write('<style type="text/css">.gm-style{font-family:Roboto,Arial,sans-serif;font-size:11px;font-weight:400;text-decoration:none}.gm-style img{max-width:none}</style> \n')
writeIndexFile.write('<style type="text/css"> \n')
writeIndexFile.write("html { height: 100% } \n")
writeIndexFile.write("body { height: 100%; margin: 0; padding: 0 } \n")
writeIndexFile.write("  #map_canvas { height: 100% } \n")
writeIndexFile.write(" \n")
writeIndexFile.write("</style> \n")
writeIndexFile.write(" \n")
writeIndexFile.write('<script src="http://maps.googleapis.com/maps/api/js?libraries=geometry&key=PUTYOURKEYHERE"></script> \n')
writeIndexFile.write(" \n")
writeIndexFile.write("<script> \n")
writeIndexFile.write("//var myCenter=new google.maps.LatLng(28.508742,-70.120850); \n")
writeIndexFile.write('var myLocation=new google.maps.LatLng(' + HomeLat + "," + HomeLong + '); var opt = ' + '{' + 'minZoom: 2}; \n')
writeIndexFile.write("//var chicago = " + "{" + "lat: 41.85, lng: -87.65};  var opt = " + "{" + "minZoom: 3}; \n")
writeIndexFile.write(" \n")
writeIndexFile.write("function initialize() { \n")
writeIndexFile.write("  var mapProp = { \n")
writeIndexFile.write("    center:myLocation, \n")
writeIndexFile.write("    zoom:3, \n")
writeIndexFile.write("    mapTypeId:google.maps.MapTypeId.ROADMAP \n")
writeIndexFile.write("    }; \n")
writeIndexFile.write(" \n")
writeIndexFile.write('  var map=new google.maps.Map(document.getElementById("googleMap"),mapProp); \n')
writeIndexFile.write(" \n")

# Create points and linles from data in Connections File

for item in ConnectionsSeen:
    thisline = item.split(",")
    if len(thisline) == 10:
        lcolor = ""
        pktnum = str(thisline[0])
        timestamp = thisline[1]
        srcip = thisline[2].split(":")[0]
        srcport = thisline[2].split(":")[1].strip()
        dstip = thisline[3].split(":")[0]
        dstport = str(thisline[3].split(":")[1].strip())
        proto = thisline[4]
        dstlat = str(thisline[5])
        dstlong = str(thisline[6])
        city = str(thisline[7].strip())
        country = str(thisline[8].strip())
        zip = str(thisline[9].strip())
        if proto == "ICMP":
            lcolor = "green"
        elif proto == "UDP":
            lcolor = "blue"
        else:
            lcolor = "red"
          
        writeIndexFile.write('    const endPoint' + pktnum + ' = new google.maps.LatLng(' + dstlat + ", " + dstlong + '); \n')
        writeIndexFile.write('    const geodesicLine' + pktnum + ' = new google.maps.Polyline({ path: [myLocation, endPoint' + pktnum +'], geodesic: true, strokeColor: ' + "'" + lcolor + "'" + ', strokeOpacity: 1.0, strokeWeight: 3 }); \n')
        writeIndexFile.write('    const marker' + pktnum + ' = new google.maps.Marker({ position: endPoint' + pktnum + ', map: map, title: "Packet ' + pktnum + '"' + ', }); \n')
        writeIndexFile.write('    const infoWindow' + pktnum + ' = new google.maps.InfoWindow({ content: "Packet ' + pktnum + '<p>' + srcip + ' to ' + dstip + '</p><p>' + proto + ' ' + srcport + " to " + dstport + '</p><p>' + dstlat + ', ' + dstlong + '</p><p>' + city + ', ' + country + ', ' + zip + '</p>", }); \n')
        writeIndexFile.write('    marker' + pktnum + '.addListener("click", function() { infoWindow' + pktnum + '.open(map, marker' + pktnum + '); }); \n')
        writeIndexFile.write('    geodesicLine' + pktnum + '.setMap(map); \n')
        writeIndexFile.write(" \n")
                             
writeIndexFile.write("  // When the user clicks, open an infowindow \n")
writeIndexFile.write(" map.data.addListener('click', function(event) { \n")
writeIndexFile.write('      var myHTML = event.feature.getProperty("description"); \n')
writeIndexFile.write('      infowindow.setContent("<div style=' + "'" + 'width:300px; text-align: center;' + "'" + '>' + '"' + '+myHTML+"</div>"); \n')
writeIndexFile.write("      infowindow.setPosition(event.feature.getGeometry().get()); \n")
writeIndexFile.write("      infowindow.setOptions(" + "{" + "pixelOffset: new google.maps.Size(0,-30)}); \n")
writeIndexFile.write("      infowindow.open(map); \n")
writeIndexFile.write("      });  \n")
writeIndexFile.write("  map.setOptions(opt); \n")
writeIndexFile.write("  //}, 1000);        // **************************  Add me back for real-time updates ********************** \n")
writeIndexFile.write(" \n")
writeIndexFile.write("// Create the DIV to hold the control and call the CenterControl() \n")
writeIndexFile.write("  // constructor passing in this DIV. \n")
writeIndexFile.write("  var centerControlDiv = document.createElement('div'); \n")
writeIndexFile.write("  var centerControl = new CenterControl(centerControlDiv, map); \n")
writeIndexFile.write(" \n")
writeIndexFile.write("  centerControlDiv.index = 1; \n")
writeIndexFile.write("  map.controls[google.maps.ControlPosition.TOP_CENTER].push(centerControlDiv); \n")
writeIndexFile.write(" \n")
#writeIndexFile.write("  var rightControlDiv = document.createElement('div'); \n")
#writeIndexFile.write("  var rightControl = new RightControl(rightControlDiv, map); \n")
#writeIndexFile.write(" \n")
#writeIndexFile.write("  rightControlDiv.index = 1; \n")
#writeIndexFile.write("  map.controls[google.maps.ControlPosition.TOP_CENTER].push(rightControlDiv); \n")
writeIndexFile.write("}  ///////////////////  this is the end of the initialize fuction  ////////////////// \n")
writeIndexFile.write(" \n")
writeIndexFile.write("google.maps.event.addDomListener(window, 'load', initialize); \n")
writeIndexFile.write(" \n")
writeIndexFile.write("</script> \n")
writeIndexFile.write("</head> \n")
writeIndexFile.write(" \n")
writeIndexFile.write("<body> \n")
writeIndexFile.write(" \n")
writeIndexFile.write('<div id="googleMap" style="width:80%;float:left;height: 100%;"></div> \n')
writeIndexFile.write(" \n")
writeIndexFile.write('<div id="Right"> \n')
writeIndexFile.write('    <iframe src="right.html" style="position:absolute;width:19.8%;float:right;height:99.6%;"></iframe> \n"')
writeIndexFile.write("    </div> \n")
writeIndexFile.write("</body> \n")
writeIndexFile.write(" \n")
writeIndexFile.write("</html>  \n")
writeIndexFile.write(" \n")
writeIndexFile.close()

#  **********************************************  Now that the main page is written, time to right data to the rightmost iFrame ********************************
rightfile = open("/var/www/html/right.html", 'w')   
rightfile.write("<!DOCTYPE html> \n")
rightfile.write('<meta http-equiv="content-type" content="text/html; charset=UTF-8">  \n')
rightfile.write("<title> Connections </title>  \n")
rightfile.write(" \n")
rightfile.write("<!-- The style tag sets CSS parameters for the page --> \n")
rightfile.write("<!-- Good color list: http://www.w3schools.com/colors/colors_names.asp --> \n")
rightfile.write(" \n")
rightfile.write("<style> \n")
rightfile.write("body	{background-color: Beige;} \n")
rightfile.write("p	{font-size: 80%; display:inline} \n")
rightfile.write("</style> \n")
rightfile.write(' \n')
rightfile.write('<h4>Connections Seen: <a href="/logs/" target="logs"> Click for logs</a> \n')
rightfile.write('<a href="/maps/" target="maps"> Click for saved maps</a> \n')
rightfile.write('<font color="red">RED=TCP</font> \n')
rightfile.write('<font color="blue">BLUE=UDP</font> \n')
rightfile.write('<font color="green">GREEN=ICMP</font> \n')
rightfile.write('_____________________________________________________________</h4> \n')
rightfile.write(' \n')
rightfile.write('<!-- This is place in the .html where the server data (string) will be; this creates the streaming effect in the right frame --> \n')
rightfile.write(' \n')
rightfile.write(' \n')

SnifferFile = open("/tmp/tempfile", 'r')
AllConnectionsSeen = SnifferFile.readlines()
for item in AllConnectionsSeen:
    print(item)
    RightStuff = str(item.split(",")[2]) + " to " + str(item.split(",")[3]) + " " + str(item.split(",")[7]) + "," + str(item.split(",")[8])
    #print("RightStuff is: " + RightStuff + "\n")
    if str(item.split(",")[4]) == "ICMP":
        fontcolor = "green"
    elif str(item.split(",")[4]) == "UDP":
        fontcolor = "blue"
    else:
        fontcolor = "red"
    rightfile.write('<font color="' + fontcolor + '">' + RightStuff + '</font><br> \n')

rightfile.write(' \n')
rightfile.write('</html> \n')
f.close()

# ************************************* Now that the CSV has been read, and the main map built, time to populate the logs and maps
# ************************************* First up is to split the CSV into rolling log files

RollingRate = ""
TapAndMapconf = open("/var/www/TapAndMap.conf","r")
for line in TapAndMapconf:
    if "LogRun" in line:
        RollingRate = line[line.find('{')+1:line.rfind('}')]
        print("Log will split every " + str(RollingRate) + " minutes")

from datetime import datetime, timedelta
from collections import defaultdict

def split_logs_by_N_minutes(input_file):
    logs_by_time = defaultdict(list)
    
    with open(input_file, 'r') as file:
        for line in file:
            if "2025" in line:
                # Extract timestamp and other log information
                # Assuming timestamp is at the beginning of the line, e.g., '2025-02-16 12:34:56 log message'
                #print(line)
                timestamp_str = line
                timestamp_str = timestamp_str.split(",")[1]
                #print(timestamp_str)             
                log_message = line
                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')

                # Round the timestamp down to the nearest 5-minute interval
                # Calculate number of minutes since the start of the hour
                minutes = (timestamp.minute // int(RollingRate)) * int(RollingRate)
                rounded_timestamp = timestamp.replace(minute=minutes, second=0, microsecond=0)

                # Store logs grouped by the rounded timestamp
                logs_by_time[rounded_timestamp].append(log_message.strip())
    
    # Write logs to separate files or handle as needed
    for rounded_timestamp, logs in logs_by_time.items():
        filename = f'/var/www/html/logs/{rounded_timestamp.strftime("%Y-%m-%d_%H-%M")}_Connections.txt'
        with open(filename, 'w') as outfile:
            outfile.write("\n".join(logs))
            print(filename + " written.")

# Call the function with your file path
split_logs_by_N_minutes('/tmp/tempfile')

# ************************************* Last up is to read in the log files and make individual maps of them  **************************************************
from os import walk  #To list directories

HomePoint = ""
    # Read in TapAndMap.conf and get necessary info
Config_F = open("/var/www/TapAndMap.conf", 'r')
HomeLat = ""
HomeLong = ""
for line in Config_F:
    if "HomeLat" in line:
        HomeLat = str(line)
        HomeLat = HomeLat[HomeLat.find('{')+1:HomeLat.rfind('}')]
    elif "HomeLong" in line:
        HomeLong = line
        HomeLong = HomeLong[HomeLong.find('{')+1:HomeLong.rfind('}')]
    HomePoint = str(HomeLat + " " + str(HomeLong))
Config_F.close()
#print("HomePoint is: " + HomePoint)

filenames = next(walk("/var/www/html/logs/"), (None, None, []))[2]  # [] if no file
#print(filenames)
for filename in filenames:
    ConnectionsSeen = []
    #print(filename)
    f = open("/var/www/html/logs/" + filename, 'r')
    AllConnectionsSeen = f.readlines()
    for item in AllConnectionsSeen:
        #print(item)
        getcoords = str(item.split(",")[5:6]) + "," + str(item.split(",")[6:7])
        getcoords = getcoords.replace("[", "")
        getcoords = getcoords.replace("]", "")
        getcoords = getcoords.replace("'", "")
        #print("Coords are: " + getcoords + "\n")
        if getcoords not in str(ConnectionsSeen) and "None" not in getcoords:   # To save markers, only add ones you've not already seen
            ConnectionsSeen.append(item)

    #print(ConnectionsSeen)

    htmlfile = "/var/www/html/maps/" + filename.split(".")[0] +  "_map.html"
    writeHTMLfile = open(htmlfile, 'w')
    writeHTMLfile.write("<!DOCTYPE html> \n")
    writeHTMLfile.write('<meta http-equiv="content-type" content="text/html; charset=UTF-8"> \n')
    writeHTMLfile.write("<title> " + filename.split(".")[0] + " Map </title> \n")
    writeHTMLfile.write('<style type="text/css">.gm-style .gm-style-mtc label,.gm-style .gm-style-mtc div{font-weight:400}</style> \n')
    writeHTMLfile.write('<style type="text/css">.gm-style .gm-style-cc span,.gm-style .gm-style-cc a,.gm-style .gm-style-mtc div{font-size:10px}</style> \n')
    writeHTMLfile.write('<style type="text/css">@media print {  .gm-style .gmnoprint, .gmnoprint {    display:none  }}@media screen {  .gm-style .gmnoscreen, .gmnoscreen {    display:none  }}</style> \n')
    writeHTMLfile.write('<style type="text/css">.gm-style{font-family:Roboto,Arial,sans-serif;font-size:11px;font-weight:400;text-decoration:none}.gm-style img{max-width:none}</style> \n')
    writeHTMLfile.write('<style type="text/css"> \n')
    writeHTMLfile.write("html { height: 100% } \n")
    writeHTMLfile.write("body { height: 100%; margin: 0; padding: 0 } \n")
    writeHTMLfile.write("  #map_canvas { height: 100% } \n")
    writeHTMLfile.write(" \n")
    writeHTMLfile.write("</style> \n")
    writeHTMLfile.write(" \n")
    writeHTMLfile.write('<script src="http://maps.googleapis.com/maps/api/js?libraries=geometry&key=PUTYOURKEYHERE"></script> \n')
    writeHTMLfile.write(" \n")
    writeHTMLfile.write("<script> \n")
    writeHTMLfile.write("//var myCenter=new google.maps.LatLng(28.508742,-70.120850); \n")
    writeHTMLfile.write('var myLocation=new google.maps.LatLng(' + HomeLat + "," + HomeLong + '); var opt = ' + '{' + 'minZoom: 2}; \n')
    writeHTMLfile.write("//var chicago = " + "{" + "lat: 41.85, lng: -87.65};  var opt = " + "{" + "minZoom: 3}; \n")
    writeHTMLfile.write(" \n")
    writeHTMLfile.write("//**************** This function centers the map on chicago.... need to make it restart the TapAndMap_to_File.py script  ********************* \n")
    writeHTMLfile.write(" \n")
    writeHTMLfile.write("function initialize() { \n")
    writeHTMLfile.write("  var mapProp = { \n")
    writeHTMLfile.write("    center:myLocation, \n")
    writeHTMLfile.write("    zoom:3, \n")
    writeHTMLfile.write("    mapTypeId:google.maps.MapTypeId.ROADMAP \n")
    writeHTMLfile.write("    }; \n")
    writeHTMLfile.write(" \n")
    writeHTMLfile.write('  var map=new google.maps.Map(document.getElementById("googleMap"),mapProp); \n')
    writeHTMLfile.write(" \n")

    # Create points and linles from data in Connections File

    for item in ConnectionsSeen:
        thisline = item.split(",")
        if len(thisline) == 10:
            lcolor = ""
            pktnum = str(thisline[0])
            timestamp = thisline[1]
            srcip = thisline[2].split(":")[0]
            srcport = thisline[2].split(":")[1].strip()
            dstip = thisline[3].split(":")[0]
            dstport = str(thisline[3].split(":")[1].strip())
            proto = thisline[4]
            dstlat = str(thisline[5])
            dstlong = str(thisline[6])
            city = str(thisline[7].strip())
            country = str(thisline[8].strip())
            zip = str(thisline[9].strip())
            if proto == "ICMP":
                lcolor = "green"
            elif proto == "UDP":
                lcolor = "blue"
            else:
                lcolor = "red"
            
            writeHTMLfile.write('    const endPoint' + pktnum + ' = new google.maps.LatLng(' + dstlat + ", " + dstlong + '); \n')
            writeHTMLfile.write('    const geodesicLine' + pktnum + ' = new google.maps.Polyline({ path: [myLocation, endPoint' + pktnum +'], geodesic: true, strokeColor: ' + "'" + lcolor + "'" + ', strokeOpacity: 1.0, strokeWeight: 3 }); \n')
            writeHTMLfile.write('    const marker' + pktnum + ' = new google.maps.Marker({ position: endPoint' + pktnum + ', map: map, title: "Packet ' + pktnum + '"' + ', }); \n')
            writeHTMLfile.write('    const infoWindow' + pktnum + ' = new google.maps.InfoWindow({ content: "Packet ' + pktnum + '<p>' + srcip + ' to ' + dstip + '</p><p>' + proto + ' ' + srcport + " to " + dstport + '</p><p>' + dstlat + ', ' + dstlong + '</p><p>' + city + ', ' + country + ', ' + zip + '</p>", }); \n')
            writeHTMLfile.write('    marker' + pktnum + '.addListener("click", function() { infoWindow' + pktnum + '.open(map, marker' + pktnum + '); }); \n')
            writeHTMLfile.write('    geodesicLine' + pktnum + '.setMap(map); \n')
            writeHTMLfile.write(" \n")
                                
    writeHTMLfile.write("  // When the user clicks, open an infowindow \n")
    writeHTMLfile.write(" map.data.addListener('click', function(event) { \n")
    writeHTMLfile.write('      var myHTML = event.feature.getProperty("description"); \n')
    writeHTMLfile.write('      infowindow.setContent("<div style=' + "'" + 'width:300px; text-align: center;' + "'" + '>' + '"' + '+myHTML+"</div>"); \n')
    writeHTMLfile.write("      infowindow.setPosition(event.feature.getGeometry().get()); \n")
    writeHTMLfile.write("      infowindow.setOptions(" + "{" + "pixelOffset: new google.maps.Size(0,-30)}); \n")
    writeHTMLfile.write("      infowindow.open(map); \n")
    writeHTMLfile.write("      });  \n")
    writeHTMLfile.write("  map.setOptions(opt); \n")
    writeHTMLfile.write(" \n")
    writeHTMLfile.write("}  ///////////////////  this is the end of the initialize fuction  ////////////////// \n")
    writeHTMLfile.write(" \n")
    writeHTMLfile.write("google.maps.event.addDomListener(window, 'load', initialize); \n")
    writeHTMLfile.write(" \n")
    writeHTMLfile.write("</script> \n")
    writeHTMLfile.write("</head> \n")
    writeHTMLfile.write(" \n")
    writeHTMLfile.write("<body> \n")
    writeHTMLfile.write(" \n")
    writeHTMLfile.write('<div id="googleMap" style="width:100%;float:left;height: 100%;"></div> \n')
    writeHTMLfile.write(" \n")
    writeHTMLfile.write("</body> \n")
    writeHTMLfile.write(" \n")
    writeHTMLfile.write("</html>  \n")
    writeHTMLfile.write(" \n")
    writeHTMLfile.close()
    print(htmlfile + " written.")
