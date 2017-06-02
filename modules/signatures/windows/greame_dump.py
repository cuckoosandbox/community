# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import traceback
import yara
import struct
import re
import string
import pefile

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger(__name__) 

def config(data):
    finalConfig = {}
    config = configExtract(data)
    if config != None and len(config) > 20:
        domains = ""
        ports = ""
        #Config sections 0 - 19 contain a list of Domains and Ports
        for x in range(0,19):
            if len(config[x]) > 1:
                domains += xorDecode(config[x]).split(':')[0]
                domains += "|"
                ports += xorDecode(config[x]).split(':')[1]
                ports += "|"
            
        finalConfig["Domain"] = domains
        finalConfig["Port"] = ports
        finalConfig["ServerID"] = xorDecode(config[20])
        finalConfig["Password"] = xorDecode(config[21])
        finalConfig["Install Flag"] = xorDecode(config[22])
        finalConfig["Install Directory"] = xorDecode(config[25])
        finalConfig["Install File Name"] = xorDecode(config[26])
        finalConfig["Active X Startup"] = xorDecode(config[27])
        finalConfig["REG Key HKLM"] = xorDecode(config[28])
        finalConfig["REG Key HKCU"] = xorDecode(config[29])
        finalConfig["Enable Message Box"] = xorDecode(config[30])
        finalConfig["Message Box Icon"] = xorDecode(config[31])
        finalConfig["Message Box Button"] = xorDecode(config[32])
        finalConfig["Install Message Title"] = xorDecode(config[33])
        finalConfig["Install Message Box"] = xorDecode(config[34]).replace('\r\n', ' ')
        finalConfig["Activate Keylogger"] = xorDecode(config[35])
        finalConfig["Keylogger Backspace = Delete"] = xorDecode(config[36])
        finalConfig["Keylogger Enable FTP"] = xorDecode(config[37])
        finalConfig["FTP Address"] = xorDecode(config[38])
        finalConfig["FTP Directory"] = xorDecode(config[39])
        finalConfig["FTP UserName"] = xorDecode(config[41])
        finalConfig["FTP Password"] = xorDecode(config[42])
        finalConfig["FTP Port"] = xorDecode(config[43])
        finalConfig["FTP Interval"] = xorDecode(config[44])
        finalConfig["Persistance"] = xorDecode(config[59])
        finalConfig["Hide File"] = xorDecode(config[60])
        finalConfig["Change Creation Date"] = xorDecode(config[61])
        finalConfig["Mutex"] = xorDecode(config[62])        
        finalConfig["Melt File"] = xorDecode(config[63])        
        finalConfig["Startup Policies"] = xorDecode(config[69])
        finalConfig["USB Spread"] = xorDecode(config[70])
        finalConfig["P2P Spread"] = xorDecode(config[71])
        finalConfig["Google Chrome Passwords"] = xorDecode(config[73])      
        if xorDecode(config[57]) == 0:
            finalConfig["Process Injection"] = "Disabled"
        elif xorDecode(config[57]) == 1:
            finalConfig["Process Injection"] = "Default Browser"
        elif xorDecode(config[57]) == 2:
            finalConfig["Process Injection"] = xorDecode(config[58])
        else: finalConfig["Process Injection"] = "None"
    else:
        return None
    print xorDecode(config[33]).encode('hex')
    return finalConfig
    
        
#Helper Functions Go Here
def configExtract(rawData):
    try:
        pe = pefile.PE(data=rawData)
        try:
          rt_string_idx = [
          entry.id for entry in 
          pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_RCDATA'])
        except ValueError, e:
            sys.exit()
        except AttributeError, e:
            sys.exit()
        rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
        for entry in rt_string_directory.directory.entries:
            if str(entry.name) == "GREAME":
                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                config = data.split('####@####')
                return config
    except:
        return None

def xorDecode(data):
    key = 0xBC
    encoded = bytearray(data)
    for i in range(len(encoded)):
        encoded[i] ^= key
    return filter(lambda x: x in string.printable, str(encoded))


class GreameDump(Signature):
    name = "greame_dump"
    description = "Greame RAT has been indentified (config has been dumped)"
    severity = 5
    categories = ["malware", "rat"]
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"

    def on_yara(self, category, filepath, match):
        if match.name != "Greame":
            return

        cfg = None
        try:
            cfg = config(open(filepath, 'rb').read())
        except Exception as e:
            traceback.print_exc()
            pass

        if not cfg:
            return

        cfg["family"] = "Greame RAT"
        cfg["cnc"] = cfg["Domain"]
        cfg["type"] = cfg["ServerID"]
        self.mark_config(cfg)
        return True
