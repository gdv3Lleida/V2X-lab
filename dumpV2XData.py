
# Extract V2X data from pcapng file to display in Kepler
# Author: Dominik Schoop
# Version: 28.05.2025
import subprocess
# Example of dumping data with tshark
# "C:\Program Files\Wireshark\tshark" -r CAM.pcapng -e its.messageId -e
tshark_cmd = [
    "C:/Program Files/Wireshark/tshark",
    "-r", "C:/Users/gerard/Downloads/Altres/Trace_HE_250422.pcapng",
    "-e", "its.messageId",
    "-e", "its.stationId",
    "-e", "its.latitude",
    "-e", "its.longitude",
    "-Tfields"
]

result = subprocess.run(tshark_cmd, capture_output=True, text=True)
# Item lists are dumped by tshark as comma separated list
import os
import time
import sys, shlex
import subprocess
import argparse
from copy import deepcopy
from pyproj import Proj, Transformer
from shapely.geometry import Point, MultiPoint, LineString 
from shapely.ops import transform

tshark = '\"C:/Program Files/Wireshark/tshark\"'

# Getting certificates
# https://cpoc.jrc.ec.europa.eu/L1/gettlmcertificate/

"""
The following data structures define which and how data is written
to CSV file.
The data structure is a tuple (filterstring, pcapfields, csvfields, statfields).
filterstring: display filter that is applied to the data before dumping
pcapfields:   dictionary of message fields to be extractetd
              indexed by arbitrary chosen names
csvfields:    field names that will be stored in CSV file
              The value for the field names is taken directly from
              pcapfields or is computed based on pcapfields.
statfields:   list of tuples (field name, statistics type)
              For the given field names, a statistic of the statistic type
              will be printed at the end of writing the CSV file.
              Possible statistic types are:
              count  - counts the number of distinct values
              list   - returns list of all values occurring
              minmax - returns tuple of minimal and maximal value (ints)
"""

# Helping dictionaries and lists to build the data structures
gn_addr_dict = {
        "geomid"   : "geonw.src_pos.addr.mid", # 'MAC' address of ITS station
        "addrType" : "geonw.src_pos.addr.type", # type of ITS station, e.g. RSU
        "country"  : "geonw.src_pos.addr.country", # country code
        "tst"      : "geonw.src_pos.tst",   # ms since 1.1.2004 mod 2^32
        "GNlat"    : "geonw.src_pos.lat",   # in 1/10 micro degree
        "GNlon"    : "geonw.src_pos.long",  # in 1/10 micro degree
        "GNspeed"  : "geonw.src_pos.speed"  # in cm/s
    }

gn_addr_cvslist = [
        "geomid",
        "seqnr",    # generates a sequential message number for each geomid
        "addrType",
        "country",
        "tst",
        "GNwkt"     # generates WKT string for position suitable for Kepler.gl
    ]

gxc_dict = {
        **gn_addr_dict,
        "GXClat"    : "geonw.gxc.latitude",
        "GXClon"    : "geonw.gxc.longitude",
        "GXCradius" : "geonw.gxc.radius",
    }

gxc_cvslist = gn_addr_cvslist + [ "GXCwktpoint", "GXCwktcircle" ]

its_dict = {
        "mid"       : "its.messageId",
        "sid"       : "its.stationId",
        "ITSlat"    : "its.latitude",      # in 1/10 micro degree
        "ITSlon"    : "its.longitude",     # in 1/10 micro degree
        "ITSalt"    : "its.altitudeValue",
        "speed"     : "its.speedValue",          # in cm/s
        "deltalat"  : 'its.deltaLatitude',
        "deltalon"  : 'its.deltaLongitude',
        "deltaalt"  : 'its.deltaAltitude',
        "deltatime" : 'its.pathDeltaTime'
    }

its_cvslist = [ "mid", "sid", "ITSwkt", "speed" ]


sig_dict = {
        # https://www.wireshark.org/docs/dfref/i/ieee1609dot2.html
        "hashId" : "ieee1609dot2.hashId", # 0 = sha256
        "digest" : "ieee1609dot2.digest",
        "unsecuredData" : "ieee1609dot2.unsecuredData",
        "certVersion" : "ieee1609dot2.version",
        "certType" : "ieee1609dot2.type",
        "certIssuer" : "ieee1609dot2.issuer",
        "id" : "ieee1609dot2.id",
        "cracaId" : "ieee1609dot2.cracaId",
        "certSha256AndDigest" : "ieee1609dot2.sha256AndDigest",
        "certAppPermissions" : "ieee1609dot2.appPermissions",
        "certCompressed_y_0" : "ieee1609dot2.compressed_y_0",
        "certX-only" : "ieee1609dot2.x_only",
        "certSSig" : "ieee1609dot2.sSig",
        "compressed-y-1" : "ieee1609dot2.compressed_y_1"
    }


sig_csvlist = list(sig_dict.keys())


# Data structures to dump message from pcapng to CVS files
# (filter string, field name directory, cvs field names, fields with statistics)
gn_addr_info = ('its.messageId >= 0', gn_addr_dict, gn_addr_cvslist,
    [ ("geomid", "count"), ("addrType", "list"), ("country", "list") ] )

gnsec_info = ('its.messageId >= 0', { **gn_addr_dict, **sig_dict },
              gn_addr_cvslist + sig_csvlist,
    [ ("geomid", "count"), ("addrType", "list"), ("country", "list"),
("certVersion", "list"), ("certType", "list"), ("certIssuer", "list"), ("id",
"list"), ("cracaId", "list") ] )


# Definition for CAM
cam_info = ('its.messageId == 2', {
        **gn_addr_dict,
        **its_dict,
        "sType"  : "its.stationType",  # 5 = passenger car
        "length" : "its.vehicleLengthValue",  # in dm
        "width"  : "cam.vehicleWidth",        # in dm
        "vehicleRole" : "cam.vehicleRole",
        "pathHistory" : "cam.pathHistory"
    },
    gn_addr_cvslist + its_cvslist + [ "sType", "length", "width", "vehicleRole",
"pathHistoryWKT" ],
    [ ("geomid", "count"), ("sType", "list"), ("speed","minmax"), ("length","list"),
("width","list"), ("vehicleRole","list") ]
    )


# Definition for DENM
denm_info = ('its.messageId == 1', {
        **gxc_dict,
        **its_dict,
        "origid"            : "its.originatingStationId",
        "sequenceNumber"    : "its.sequenceNumber", 
        "dettime"           : "denm.detectionTime",
        "reftime"           : "denm.referenceTime",
        "awarenessDistance" : "denm.awarenessDistance",
        "awarenessTrafficDirection" : "denm.awarenessTrafficDirection",
        "validityDuration"  : "denm.validityDuration",
        "ccAndScc"          : "its.ccAndScc",
        "traces"            : "denm.traces",
        "sType"             : "denm.stationType"
    },
    gxc_cvslist + its_cvslist + [ "origid", "sequenceNumber", "dettime", "reftime",
"ccAndScc", "ITSawarenes", "tracesWKT" ],
    [ ("geomid", "count"), ("sType", "list"), ("awarenessDistance", "list"),
("awarenessTrafficDirection","list"), ("validityDuration","list"), ("ccAndScc",
"list") ]
    )


# Data structure (mid, pcapfields, csvfiels) for MAPEM
# https://docs.ros.org/en/humble/p/etsi_its_mapem_ts_msgs/msg/MapData.html
mapem_tshark_info = ('5', {
        "geomid" : "geonw.src_pos.addr.mid",
        "tst"    : "geonw.src_pos.tst", # ms since 1.1.2004 mod 2^32
        "GNlat"  : "geonw.src_pos.lat",      # in 1/10 micro degree
        "GNlon"  : "geonw.src_pos.long",     # in 1/10 micro degree
        "intersections" : "dsrc.intersections",
        "name"      : "dsrc.name",
        "DSRClat"   : "dsrc.lat",
        "DSRClon"   : "dsrc.long",
        "laneWidth" : "dsrc.laneWidth",
        "laneSet"   : "dsrc.laneSet",
        "nodes"     : "dsrc.nodes",
        "x" : "dsrc.x",
        "y" : "dsrc.y",
        #"GXClat" : "geonw.gxc.latitude",
        #"GXClon" : "geonw.gxc.longitude",
        #"GXCradius" : "geonw.gxc.radius",
        #"mid"    : "its.messageId",
        #"sid"    : "its.stationId",
        #"origid" : "its.originatingStationId",
        #"seqnr"  : "its.sequenceNumber", 
        #"dettime" : "denm.detectionTime",
        #"reftime" : "denm.referenceTime",
        #"awaredist" : "denm.awarenessDistance",
        #"valdur" : "denm.validityDuration",
        #"ccAndScc" : "its.ccAndScc",
        #"traces"  : "denm.traces",
        #"ITSlat" : "its.latitude",    # in 1/10 micro degree
        #"ITSlon" : "its.longitude",   # in 1/10 micro degree
        #"alt"    : "its.altitudeValue",
        #"speed"  : "its.speedValue",          # in m/s
        #"length" : "its.vehicleLengthValue",  # in dm
        #"width"  : "cam.vehicleWidth",    # in dm
        #"campath" : "cam.pathHistory",
        #"pathpoint" : 'packet.ITS.pathpoint_element',
        #"pathposition" : 'packet.ITS.pathposition_element',
        #"itsPath"  : 'its.Path',
        #"deltalat" : 'its.deltaLatitude',
        #"deltalon" : 'its.deltaLongitude',
        #"deltaalt" : 'its.deltaAltitude',
        #"deltatime" : 'its.pathDeltaTime',
        #"seq" : 'packet.ITS.per_sequence_of_length',
        #"deltalat2" : 'packet.ITS.item 0',
    }, [ "geomid", "tst", "GNwkt", "intersections", "name", "DSRCwkt", "laneWidth",
"laneSet", "lanewkt" ])


# Message info for all message types
message_info = { 'GN' : gn_addr_info, 'GNSEC' : gnsec_info, 'CAM' : cam_info, 'DENM'
: denm_info }


# Data structure (filterstring, pcapfields, csvfields, statfields)
gnw_sec_tshark_info = ('its.messageId >= 0', {
        "geomid" : "geonw.src_pos.addr.mid",
        "addType" : "geonw.src_pos.addr.type",
        "tst"    : "geonw.src_pos.tst",   # ms since 1.1.2004 mod 2^32
        "GNlat"  : "geonw.src_pos.lat",   # in 1/10 micro degree
        "GNlon"  : "geonw.src_pos.long",  # in 1/10 micro degree
        # https://www.wireshark.org/docs/dfref/i/ieee1609dot2.html
        "hashId" : "ieee1609dot2.hashId", # 0 = sha256
        "digest" : "ieee1609dot2.digest",
        "unsecuredData" : "ieee1609dot2.unsecuredData",
        "certVersion" : "ieee1609dot2.version",
        "certType" : "ieee1609dot2.type",
        "certIssuer" : "ieee1609dot2.issuer",
        "certSha256AndDigest" : "ieee1609dot2.sha256AndDigest",
        "certAppPermissions" : "ieee1609dot2.appPermissions",
        "certCompressed_y_0" : "ieee1609dot2.compressed_y_0",
        "certX-only" : "ieee1609dot2.x_only",
        "certSSig" : "ieee1609dot2.sSig",
        "compressed-y-1" : "ieee1609dot2.compressed_y_1"
    },
    [ "geomid",
      "seqnr",
      "tst",
      "GNwkt",
      "hashId",
      "digest",
      "certVersion",
      "certType",
      "certIssuer",
      "certSha256AndDigest",
      "certAppPermissions",
      "certCompressed_y_0",
      "certX-only",
      "certSSig",
      "compressed-y-1"],
    [ ("geomid", "count"),
      ("hashId", "count"),
      ("digest", "count"),
      ("certVersion", "list"),
      ("certType", "list"),
      ("certIssuer", "list")
    ]
    )


# Geometric helper functions

# Transformer functions from degree to meter to calculate distances etc.
lonES = 9.30900
latES = 48.74122
# Local Azimuthal Equidistant projection, centered on the 'origin' parameter
crs_aeqd = Proj(proj='aeqd', datum='WGS84', lon_0=lonES, lat_0=latES, units='m').crs
# Definition of transformer functions
from_wgs84_to_aeqd = Transformer.from_crs("EPSG:4326", crs_aeqd,
always_xy=True).transform
from_aeqd_to_wgs84 = Transformer.from_crs(crs_aeqd, "EPSG:4326",
always_xy=True).transform
    
# Calculate circle polygon of given radius (in m) around center = (lon,lat)
def calc_circle(lon, lat, radius):
    flon = float(lon)
    flat = float(lat)
    iradius = int(radius)
    center_wgs84 = Point(flon,flat)
    center_aeqd = transform(from_wgs84_to_aeqd, center_wgs84)
    circle_aeqd = center_aeqd.buffer(iradius)
    circle_wgs84 = transform(from_aeqd_to_wgs84, circle_aeqd)
    return circle_wgs84.wkt


###########################################################
# Helper functions

# Enclose string with "
def apo(s):
    return "\""+s+"\""

# Convert microdegree (int or string) to degree (string)
def int2degree(value):
    return str(int(value)*1.0/10000000)

def getseqnr(dictionary, key):
    if key in dictionary.keys():
        dictionary[key] += 1
    else:
        dictionary[key] = 1
    return dictionary[key]

############################################################
# Extraction functions

# Extract message values from pcap(ng) file with tshark and write them to text file
def pcap2txt(pcapfile, outfile, packet_info):
    print(f'Extracting field values from pcapng file {pcapfile} ...')
    fstr, fields, compfields, _ = packet_info
    # construct filter string for tshark
    if len(fstr)>0:
        filterstr = f' -2 -R \"{fstr}\"'
    else:
        filterstr = ''
    # construct field selection for tshark
    fieldsstr = " -e ".join(fields.values())
    fieldsstr = " -Tfields -E separator=; -e "+fieldsstr
    cmdstr = tshark + ' -r \"' + pcapfile + '\"' + filterstr + fieldsstr + ' > ' + outfile
    #print(cmdstr)
    process = subprocess.Popen(shlex.split(cmdstr), stdout=subprocess.PIPE,
stderr=subprocess.PIPE, shell=True, cwd=".")
    stdout, stderr = process.communicate()
    if len(stdout)>0:
        print("stdout:", stdout)
    if len(stderr)>0:
        print("stderr:", stderr)
    #process.kill()


# Wrapper for extract_from_pcap_wrapped to construct outfile name
def extract_from_pcap(pcapfile, outstr, packet_info):
    filename, fileext = os.path.splitext(pcapfile)
    outfile = filename + '_' + outstr + '.csv'
    extract_from_pcap_wrapped(pcapfile, outfile, packet_info)
    

# Extract message values from pcap(ng) file and write them to csv file
def extract_from_pcap_wrapped(pcapfile, outfile, packet_info):
    print(f'Extracting pcapng file {pcapfile} writing to file {outfile} ...')
    mid, fields, csvfields, statfieldsinfo = deepcopy(packet_info)
    # Prepare data structure for statistics of received packets
    stattypedict = {}
    statdict = {}
    for field,stattype in statfieldsinfo:
        stattypedict[field] = stattype
    statfields = stattypedict.keys()
    # dump relevant packages into temporary text file for parsing
    tmpfile = 'out.txt'
    pcap2txt(pcapfile, tmpfile, packet_info)
    # construct heading names and write them to outfile
    heading = '\";\"'.join(csvfields)
    heading = '\"' + heading + '\"\n'
    #print("Heading of csv file:")
    #print(heading)
    fout = open(outfile, 'w')
    fout.write(heading)
    # dictionary for sequential message counter for each station
    seqnrdict = {}
    # read data from temporary text file
    with open(tmpfile, 'r') as file:
        ctr = 0
        # read each line from file and parse the fields
        for line in file:
            res = ''
            ctr += 1
            if ctr % 5000 == 0:
                print(f'Processed {ctr} messages')
            line = line.strip('\n')
            filefields = line.split(';')
            # store field values in dictionary
            numfields = len(filefields)
            for i, k in enumerate(fields):
                if i < numfields:
                    fields[k] = filefields[i]
                else:
                    fields[k] = ''
            # add computed field values
            for k in csvfields:
                if k == "seqnr":
                    # generate a sequential number for all messages of each station
                    seqnr = getseqnr(seqnrdict,fields['geomid'])
                    res += f"{seqnr};"
                elif k == "tstshort":
                    tst = fields["tst"]
                    tst = int(tst) % 1000000
                    res += f"{tst};"
                elif k == "GNwkt":
                    lon = int2degree(fields["GNlon"])
                    lat = int2degree(fields["GNlat"])
                    res += f"\"POINT ({lon} {lat})\";"
                elif k == "GXCwktpoint":
                    lon = int2degree(fields["GXClon"])
                    lat = int2degree(fields["GXClat"])
                    res += f"\"POINT ({lon} {lat})\";"
                elif k == "GXCwktcircle":
                    lon = int2degree(fields["GXClon"])
                    lat = int2degree(fields["GXClat"])
                    circle = calc_circle(lon, lat, fields["GXCradius"])
                    res += f"{apo(circle)};"
                elif k == "ITSwkt":
                    if len(fields["ITSlon"]) > 0:
                        lon = int2degree(fields["ITSlon"])
                        lat = int2degree(fields["ITSlat"])
                        res += f"\"POINT ({lon} {lat})\";"
                    else:
                        # DENM cancellation does not contain ITS location
                        res += ";"
                elif k == "ITSawarenes":
                    if len(fields["awarenessDistance"]) > 0:
                        lon = int2degree(fields["ITSlon"])
                        lat = int2degree(fields["ITSlat"])
                        """
                        RelevanceDistance ::= ENUMERATED {
                            lessThan50m(0), 
                            lessThan100m(1), 
                            lessThan200m(2), 
                            lessThan500m(3), 
                            lessThan1000m(4), 
                            lessThan5km(5), 
                            lessThan10km(6), 
                            over10km(7)
                        }
                        """
                        ad = int(fields["awarenessDistance"])
                        distlist = [ 50, 100, 200, 500, 1000, 5000, 10000, 100000 ]
                        dist = distlist[ad]
                        circle = calc_circle(lon, lat, dist)
                        res += f"{apo(circle)};"
                    else:
                        # DENM cancellation does not contain awarenessDistance
                        res += ";"
                elif k == "pathHistoryWKT" or k == 'tracesWKT':
                    if len(fields["deltalon"]) > 0:
                        deltalonlist = fields["deltalon"].split(',')
                        deltalatlist = fields["deltalat"].split(',')
                        #print(deltalonlist)
                        #print(deltalatlist)
                        lon = int(fields["ITSlon"])
                        lat = int(fields["ITSlat"])
                        #print(lon, lat)
                        multipointstr = '\"MULTIPOINT('
                        for lonstr, latstr in zip(deltalonlist, deltalatlist):
                            lon = lon + int(lonstr)
                            lat = lat + int(latstr)
                            londegree = int2degree(lon)
                            latdegree = int2degree(lat)
                            #print(londegree, latdegree)
                            multipointstr += f"{londegree} {latdegree},"
                        multipointstr = multipointstr[:-1]+')'
                        res += multipointstr + '\";'
                    else:
                        res += ';'
                elif k == 'tracesWKT_OLD':
                    if len(fields["itsPath"]) > 0:
                        deltalonlist = fields["deltalon"].split(',')
                        deltalatlist = fields["deltalat"].split(',')
                        #print(deltalonlist)
                        #print(deltalatlist)
                        lon = int(fields["ITSlon"])
                        lat = int(fields["ITSlat"])
                        #print(lon, lat)
                        multipointstr = '\"MULTIPOINT('
                        for lonstr, latstr in zip(deltalonlist, deltalatlist):
                            lon = lon + int(lonstr)
                            lat = lat + int(latstr)
                            londegree = int2degree(lon)
                            latdegree = int2degree(lat)
                            #print(londegree, latdegree)
                            multipointstr += f"{londegree} {latdegree},"
                        multipointstr = multipointstr[:-1]+')'
                        res += multipointstr + '\";'
                    else:
                        res += ';'
                elif k == 'DSRCwkt':
                    lon = int2degree(fields["DSRClon"])
                    lat = int2degree(fields["DSRClat"])
                    res += f"\"POINT ({lon} {lat})\";"
                elif k == 'lanewkt':
                    if len(fields['laneSet']) > 0:
                        nodes = fields['nodes'].split(',')
                        deltalonlist = fields["x"].split(',')
                        deltalatlist = fields["y"].split(',')
                        lon = int(fields["DSRClon"])
                        lat = int(fields["DSRClat"])
                        numdelta = int(nodes[0])
                        multipointstr = '\"MULTIPOINT('
                        laneindex = 0
                        ctr = 0
                        print(len(deltalonlist))
                        # each node starts a new chain of relative positions
                        for lonstr, latstr in zip(deltalonlist, deltalatlist):
                            print(nodes, laneindex, ctr)
                            numdelta = int(nodes[laneindex])
                            ctr += 1
                            if ctr > numdelta:
                                ctr = 0
                                laneindex += 1
                                numdelta = int(nodes[laneindex])
                                lon = int(fields["DSRClon"])
                                lat = int(fields["DSRClat"])
                            lon = lon + int(lonstr)
                            lat = lat + int(latstr)
                            londegree = int2degree(lon)
                            latdegree = int2degree(lat)
                            #print(londegree, latdegree)
                            multipointstr += f"{londegree} {latdegree},"
                        """
                        # each item is directly relative to DSRClon, DSRClat
                        for lonstr, latstr in zip(deltalonlist, deltalatlist):
                            lontmp = lon + int(lonstr)
                            lattmp = lat + int(latstr)
                            londegree = int2degree(lontmp)
                            latdegree = int2degree(lattmp)
                            multipointstr += f"{londegree} {latdegree},"
                        """
                        multipointstr = multipointstr[:-1]+')'
                        res += multipointstr + '\";'
                else:
                    res += '\"'+fields[k]+'\";'
            # Update statistic
            for k in stattypedict.keys():
                update_statistic(k, fields, stattypedict, statdict)
            # Write line to csv file
            res = res[:-1]+"\n"
            fout.write(res)
    fout.close()
    print_statistic(stattypedict, statdict)


# Helper function to update statistic
def update_statistic(k, fields, stattypedict, statdict):
    # Do not count if not defined for statistics
    if k not in stattypedict.keys():
        return
    value = fields[k]
    stattype = stattypedict[k]
    match stattype:
        case "count":
            if k not in statdict.keys():
                statdict[k] = set([value])
            else:
                statdict[k].add(value)
        case "list":
            if k == "awarenessDistance" and value == '30':
                print(fields)
            if k not in statdict.keys():
                statdict[k] = set([value])
                
            else:
                statdict[k].add(value)
        case "minmax":
            ivalue = int(value)
            if k not in statdict.keys():
                statdict[k] = (ivalue, ivalue)
            else:
                minvalue, maxvalue = statdict[k]
                statdict[k] = (min(ivalue,minvalue), max(ivalue,maxvalue))
        case _:
            print("STATISTICS TYPE NOT DEFINED!")


def print_statistic(stattypedict, statdict):
    for k in statdict.keys():
        if stattypedict[k] == "count":
            value = len(statdict[k])
        else:
            value = statdict[k]
        print(k, value)


# Convert a csv file with CAMs into a file with trajectories
def convert_cams_to_trajectories(csvinfile, csvoutfile):
    vehicles = {}
    end = ""
    linectr = 0
    csvinfile = "CAM_output.csv"     #TODO: revisar que aixo ha estat canviat
    with open(csvinfile) as fin:
        for line in fin:
            linectr += 1
            if linectr % 100 == 0:
                print(linectr)
            fields = line.split(',')
            mid = fields[2]
            sid = fields[3]
            tst = fields[1]
            stype = fields[4]
            lat = str(fields[5])
            lon = str(fields[6])
            alt = fields[7]
            speed = fields[8]
            length = str(int(fields[9])/10.0)
            width = str(int(fields[10])/10.0)
            lat = str(int(lat)*1.0/10000000)
            lon = str(int(lon)*1.0/10000000)
            if sid in vehicles.keys():
                vehicles[sid].append((lon, lat, tst))
            else:
                vehicles[sid] = [(lon, lat, tst)]
                
    csvoutfile = "CAM_trajectories.csv"
    fout = open(csvoutfile, "w")
    fout.write("sid, track, start, end\n")
    for sid in vehicles.keys():
        print(sid)
        wktstr = "LINESTRING ("
        start = ''
        for lon,lat,tst in vehicles[id]:
            wktstr += f"{lon} {lat}, "
            if len(start) == 0:
                start = tst
            end = tst
        wktstr = wktstr[:-2] + ')'
        fout.write(f"{apo(id)},{apo(wktstr)},{apo(start)},{apo(end)}\n")
        
    fout.close()


def convertall():
    files = ['CAM.pcapng', 'DENM.pcapng', 'DENMs_Test.pcapng',
'DENM_DangerousSituation.pcapng', 'MAPEM_Birkach.pcapng',
'MAPEM_Degerloch.pcapng', 'Trace_HE_250408.pcapng', 'Trace_HE_250410.pcapng',
'Trace_HE_250410_5383.pcapng', 'Trace_HE_250415.pcapng',
'Trace_HE_250415_DangerousSituation.pcapng',
'Trace_HE_250415_StationaryVehicle.pcapng', 'Trace_HE_250416.pcapng',
'Trace_HE_250422.pcapng', 'Trace_HE_250423.pcapng', 'Trace_HE_250428.pcapng',
'Trace_HE_250429.pcapng', 'Trace_HE_250505-1.pcapng',
'Trace_HE_250505-2.pcapng', 'Trace_HE_250506.pcapng', 'Trace_ID3_250425.pcapng',
'Trace_ID3_250428.pcapng', 'Trace_ID3_250429.pcapng',
'Trace_ID3_250430-1.pcapng', 'Trace_ID3_250430-2.pcapng',
'Trace_ID3_250501_Birkach.pcapng', 'Trace_ID3_250506-1.pcapng',
'Trace_ID3_250506-2.pcapng', 'Trace_ID3_250508-1.pcapng',
'Trace_Welfen_250407.pcapng', 'Trace_Welfen_250408.pcapng',
'Trace_Welfen_250502.pcapng', 'Trace_Welfen_250507.pcapng']
    #files = ['Trace_Welfen_250502.pcapng', 'Trace_Welfen_250507.pcapng']
    #files = ['Trace_Welfen_250507.pcapng']
    for fname in files:
        print(f"Working on file {fname} ...")
        extract_from_pcap(fname, "CAM", message_info["CAM"])  #Aixo tb canviat
        time.sleep(3)
        

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--inputfile", type=str,
                        help="name of input pcap file")
    parser.add_argument("-o", "--outfile", type=str,
                        help="name of output csv file")
    parser.add_argument("-m", "--mtype", type=str,
                        help=f"name of message type to export, possible message types: {list(message_info.keys())}")

    args = parser.parse_args()
    inputfile = args.inputfile
    outfile = args.outfile
    mtype = args.mtype

    # print(f'i:{inputfile} o:{outfile} m:{mtype}')
    if inputfile is None:
        print("Usage: ... -i inputfile [-o outputfile] [-m message type]")
        print("Please provide inputfile ...")
        exit()
    if not os.path.exists(inputfile):
        print(f'Input file {inputfile} does not exist!')
        exit()
    if mtype is None:
        for mtype in message_info.keys():
            extract_from_pcap(inputfile, mtype, message_info[mtype])
        exit()
    elif mtype not in message_info.keys():
        print(f'Message type {mtype} unknown.')
        print('Valid message types are: ')
        print(list(message_info.keys()))
        print('Exiting ...')
        exit()
    if outfile is None:
        extract_from_pcap(inputfile, mtype, message_info[mtype])
    print("done.")


if __name__ == "__main__":
    main()

