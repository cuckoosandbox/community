# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
from Crypto.Cipher import ARC4
import yara
import base64
import struct
import json
import re
import string
from struct import unpack
import pefile
from binascii import *

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger(__name__) 

def config(data):
    conf = {}
    rawConfig = configExtract(data).replace('\x00', '')
    config = rawConfig.split("|")
    print config
    if config != None:
        conf["ServerID"] = config[0]
        conf["Mutex"] = config[1]
        conf["InstallName"] = config[2]
        conf["StartupName"] = config[3]
        conf["Extension"] = config[4]
        conf["Password"] = config[5]
        conf["Install Flag"] = config[6]
        conf["Startup Flag"] = config[7]
        conf["Visible Flag"] = config[8]
        conf["Unknown Flag1"] = config[9]
        conf["Unknown Flag2"] = config[10]
        conf["Port"] = config[11]
        conf["Domain"] = config[12]
        conf["Unknown Flag3"] = config[13]
    print conf
    return conf
    
        
#Helper Functions Go Here

def configExtract(rawData):

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
            if str(entry.name) == "CFG":
                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                return data



class BozokDump(Signature):
    name = "bozok_dump"
    description = "Bozok RAT has been indentified (config has been dumped)"
    severity = 5
    categories = ["malware", "rat"]
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"

    def on_yara(self, category, filepath, match):
        if match.name != "Bozok":
            return

        cfg = None
        try:
            cfg = config(open(filepath, 'rb').read())
        except Exception as e:
            pass

        if not cfg:
            return

        cfg["family"] = "Bozok RAT"
        cfg["cnc"] = cfg["Domain"]
        cfg["type"] = cfg["ServerID"]
        self.mark_config(cfg)
        return True
