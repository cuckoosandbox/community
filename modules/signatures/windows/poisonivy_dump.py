# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import yara
import json
import re
import string
from struct import unpack

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger(__name__) 

def config(data):
    # Split to get start of Config
    one = firstSplit(data)
    if one == None:
        return None
    # If the split works try to walk the strings
    two = dataWalk(one)
    # lets Process this and format the config
    three = configProcess(two)
    return three
    
        
#Helper Functions Go Here
def calcLength(byteStr):
    try:
        return unpack("<H", byteStr)[0]
    except:
        return None

def stringPrintable(line):
    return filter(lambda x: x in string.printable, line)

def firstSplit(data):
    splits = data.split('Software\\Microsoft\\Active Setup\\Installed Components\\')
    if len(splits) == 2:
        return splits[1]
    else:
        return None
        
def bytetohex(byteStr):
    return ''.join(["%02X" % ord(x) for x in byteStr]).strip()

    
def dataWalk(splitdata):
    # Byte array to make things easier
    stream = bytearray(splitdata)
    # End of file for our while loop
    EOF = len(stream)
    # offset to track position
    offset = 0
    this = []
    maxCount = 0
    while offset < EOF and maxCount < 22:
        try:
            length = calcLength(str(stream[offset+2:offset+4]))
            temp = []
            for i in range(offset+4, offset+4+length):
                temp.append(chr(stream[i]))
            dataType = bytetohex(splitdata[offset]+splitdata[offset+1])
            this.append((dataType,''.join(temp)))
            offset += length+4
            maxCount += 1
        except:
            return this
    return this

def domainWalk(rawStream):
    domains = ''
    offset = 0
    stream = bytearray(rawStream)
    while offset < len(stream):
        length = stream[offset]
        temp = []
        for i in range(offset+1, offset+1+length):
            temp.append(chr(stream[i]))
        domain = ''.join(temp)

        rawPort = rawStream[offset+length+2:offset+length+4]
        port = calcLength(rawPort)
        offset += length+4
        domains += "{0}:{1}|".format(domain, port)
    return domains  


def configProcess(rawConfig):
    configDict = {"Campaign ID" : "" , "Group ID" : "" , "Domains" : "" , "Password" : "" , "Enable HKLM" : "" , "HKLM Value" : "" , "Enable ActiveX" : "" , "ActiveX Key" : "" , "Flag 3" : "" , "Inject Exe" : "" , "Mutex" : "" , "Hijack Proxy" : "" , "Persistent Proxy" : "" , "Install Name" : "" , "Install Path" : "" , "Copy to ADS" : "" , "Melt" : "" , "Enable Thread Persistence" : "" , "Inject Default Browser" : "" , "Enable KeyLogger" : ""}
    for x in rawConfig:
        if x[0] == 'FA0A':
            configDict["Campaign ID"] = stringPrintable(x[1])
        if x[0] == 'F90B':
            configDict["Group ID"] = stringPrintable(x[1])
        if x[0] == '9001':
            configDict["Domains"] = domainWalk(x[1])
        if x[0] == '4501':
            configDict["Password"] = stringPrintable(x[1])
        if x[0] == '090D':
            configDict["Enable HKLM"] = bytetohex(x[1])
        if x[0] == '120E':
            configDict["HKLM Value"] = stringPrintable(x[1])
        if x[0] == 'F603':
            configDict["Enable ActiveX"] = bytetohex(x[1])
        if x[0] == '6501':
            configDict["ActiveX Key"] = stringPrintable(x[1])
        if x[0] == '4101':
            configDict["Flag 3"] = bytetohex(x[1])
        if x[0] == '4204':
            configDict["Inject Exe"] = stringPrintable(x[1])
        if x[0] == 'Fb03':
            configDict["Mutex"] = stringPrintable(x[1])
        if x[0] == 'F40A':
            configDict["Hijack Proxy"] = bytetohex(x[1])
        if x[0] == 'F50A':
            configDict["Persistent Proxy"] = bytetohex(x[1])
        if x[0] == '2D01':
            configDict["Install Name"] = stringPrintable(x[1])
        if x[0] == 'F703':
            configDict["Install Path"] = stringPrintable(x[1])
        if x[0] == '120D':
            configDict["Copy to ADS"] = bytetohex(x[1])
        if x[0] == 'F803':
            configDict["Melt"] = bytetohex(x[1])
        if x[0] == 'F903':
            configDict["Enable Thread Persistence"] = bytetohex(x[1])
        if x[0] == '080D':
            configDict["Inject Default Browser"] = bytetohex(x[1])
        if x[0] == 'FA03':
            configDict["Enable KeyLogger"] = bytetohex(x[1])
    return configDict

class PoisonInvyDump(Signature):
    name = "poisonivy_dump"
    description = "Poison Ivy RAT has been indentified (config has been dumped)"
    severity = 5
    categories = ["malware", "rat"]
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"

    def on_yara(self, category, filepath, match):
        if match.name != "PoisonIvy":
            return

        cfg = None
        try:
            cfg = config(open(filepath, 'rb').read())
        except Exception as e:
            pass

        if not cfg:
            return

        cfg["family"] = "PoisonIvy RAT"
        cfg["cnc"] = cfg["Domains"]
        cfg["type"] = cfg["Campaign ID"]
        self.mark_config(cfg)
        return True
