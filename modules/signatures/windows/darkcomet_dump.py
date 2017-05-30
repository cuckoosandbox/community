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
def rc4crypt(data, key):
    x = 0
    box = range(256)
    for i in range(256):
        x = (x + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = 0
    y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))
    
    return ''.join(out)

def v51_data(data, enckey):
    config = {"FWB": "", "GENCODE": "", "MUTEX": "", "NETDATA": "", "OFFLINEK": "", "SID": "", "FTPUPLOADK": "", "FTPHOST": "", "FTPUSER": "", "FTPPASS": "", "FTPPORT": "", "FTPSIZE": "", "FTPROOT": "", "PWD": ""}
    dec = rc4crypt(unhexlify(data), enckey)
    dec_list = dec.split('\n')
    for entries in dec_list[1:-1]:
        key, value = entries.split('=')
        key = key.strip()
        value = value.rstrip()[1:-1]
        clean_value = filter(lambda x: x in string.printable, value)
        config[key] = clean_value
        config["Version"] = enckey[:-4]
    return config

def v3_data(data, key):
    config = {"FWB": "", "GENCODE": "", "MUTEX": "", "NETDATA": "", "OFFLINEK": "", "SID": "", "FTPUPLOADK": "", "FTPHOST": "", "FTPUSER": "", "FTPPASS": "", "FTPPORT": "", "FTPSIZE": "", "FTPROOT": "", "PWD": ""}
    dec = rc4crypt(unhexlify(data), key)
    config[str(entry.name)] = dec
    config["Version"] = enckey[:-4]

    return config

def versionCheck(rawData):
    if "#KCMDDC2#" in rawData:
        return "#KCMDDC2#-890"
        
    elif "#KCMDDC4#" in rawData:
        return "#KCMDDC4#-890"
        
    elif "#KCMDDC42#" in rawData:
        return "#KCMDDC42#-890"

    elif "#KCMDDC42F#" in rawData:
        return "#KCMDDC42F#-890"
        
    elif "#KCMDDC5#" in rawData:
        return "#KCMDDC5#-890"

    elif "#KCMDDC51#" in rawData:
        return "#KCMDDC51#-890"
    else:
        return None

def configExtract(rawData, key):            
    config = {
        "FWB": "", 
        "GENCODE": "", 
        "MUTEX": "", 
        "NETDATA": "", 
        "OFFLINEK": "", 
        "SID": "", 
        "FTPUPLOADK": "", 
        "FTPHOST": "", 
        "FTPUSER": "", 
        "FTPPASS": "", 
        "FTPPORT": "", 
        "FTPSIZE": "", 
        "FTPROOT": "", 
        "PWD": ""
    }

    pe = pefile.PE(data=rawData)
    rt_string_idx = [
        entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries
    ].index(pefile.RESOURCE_TYPE['RT_RCDATA'])

    rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
    for entry in rt_string_directory.directory.entries:
        if str(entry.name) == "DCDATA":
            
            data_rva = entry.directory.entries[0].data.struct.OffsetToData
            size = entry.directory.entries[0].data.struct.Size
            data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
            config = v51_data(data, key)

        elif str(entry.name) in config.keys():

            data_rva = entry.directory.entries[0].data.struct.OffsetToData
            size = entry.directory.entries[0].data.struct.Size
            data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
            dec = rc4crypt(unhexlify(data), key)
            config[str(entry.name)] = filter(lambda x: x in string.printable, dec)
            config["Version"] = key[:-4]
    return config


def configClean(config):
    try:
        newConf = {}
        newConf["FireWallBypass"] = config["FWB"]
        newConf["FTPHost"] = config["FTPHOST"]
        newConf["FTPPassword"] = config["FTPPASS"]
        newConf["FTPPort"] = config["FTPPORT"]
        newConf["FTPRoot"] = config["FTPROOT"]
        newConf["FTPSize"] = config["FTPSIZE"]
        newConf["FTPKeyLogs"] = config["FTPUPLOADK"]
        newConf["FTPUserName"] = config["FTPUSER"]
        newConf["Gencode"] = config["GENCODE"]
        newConf["Mutex"] = config["MUTEX"]
        newConf["Domains"] = config["NETDATA"]
        newConf["OfflineKeylogger"] = config["OFFLINEK"]
        newConf["Password"] = config["PWD"]
        newConf["CampaignID"] = config["SID"]
        newConf["Version"] = config["Version"]
        return newConf
    except:
        return config
    
def config(data):
    versionKey = versionCheck(data)
    if versionKey != None:
        config = configExtract(data, versionKey)
        config = configClean(config)
        config["key"] = versionKey
        return config
    else:
        return None


class DarkCometDump(Signature):
    name = "dark_comet_dump"
    description = "Dark Comet RAT has been indentified (config has been dumped)"
    severity = 5
    categories = ["malware", "rat"]
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"

    def on_yara(self, category, filepath, match):
        if match.name != "DarkComet":
            return

        cfg = None
        try:
            cfg = config(open(filepath, 'rb').read())
        except Exception as e:
            pass

        if not cfg:
            return

        cfg["family"] = "DarkComet RAT"
        cfg["cnc"] = cfg["Domains"]
        cfg["type"] = cfg["Version"]
        self.mark_config(cfg)
        return True
