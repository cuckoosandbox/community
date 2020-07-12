# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import traceback
import yara
import re
import string
from struct import unpack
from Crypto.Cipher import ARC4

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger(__name__) 

def config(data):
    cfg = verDetect(data)
    return cfg

####RC4 Cipher ####    
def DecryptRC4(enckey, data):
    cipher = ARC4.new(enckey) # set the ciper
    return cipher.decrypt(data.decode('hex')) # decrpyt the data

def verDetect(data):
    first = data.split("*EDIT_SERVER*")
    if len(first) == 2:
        second = first[1].split("\r\n")
        if len(second) > 14 < 30:
            return new_decoder(second)
    first = data.split("[DATA]")
    if len(first) == 21:
        return v80(first)
    if len(first) == 30:
        return v801(first)
    return None
        

def new_decoder(split_list):
    raw_dict = {}
    for line in split_list:
        try:
            k,v = line.split(" = ")
            raw_dict[k[1:-1]] = v[1:-1]
        except:
            continue
    return config_cleaner(raw_dict)

def config_cleaner(raw_dict):
    clean_dict = {}
    for k,v in raw_dict.iteritems():
        if k == 'ip':
            clean_dict['Domain'] = DecryptRC4("oussamio", v)
        if k == 'fire':
            clean_dict['Firewall Bypass'] = v
        if k == 'foder':
            clean_dict['InstallPath'] = v
        if k == 'mlt':
            clean_dict['Melt'] = v
        if k == 'msns':
            clean_dict['MSN Spread'] = v
        if k == 'name':
            clean_dict['Reg Key'] = v
        if k == 'path':
            clean_dict['Reg value'] = v
        if k == 'port':
            clean_dict['Port'] = v
        if k == 'ppp':
            clean_dict['P2PSpread'] = v
        if k == 'reg':
            clean_dict['Registry Startup'] = v
        if k == 'usb':
            clean_dict['USB Spread'] = v
        if k == 'usbn':
            clean_dict['USB Name'] = v
        if k == 'victimo':
            clean_dict['CampaignID'] = v
    return clean_dict

def v80(conf):
    conf_dict = {}
    conf_dict["Domain"] = DecryptRC4("UniQue OussamiO", conf[1])
    conf_dict["Campaign"] = conf[2]
    conf_dict["Enable Startup"] = conf[3]
    conf_dict["StartupName"] = conf[4]
    conf_dict["FolderName"] = conf[5]
    if conf[6] == "D":
        conf_dict["Path"] = "App Data Folder"
    elif conf[6] == "W":
        conf_dict["Path"] = "Windows Folder"
    if conf[6] == "s":
        conf_dict["Path"] = "System Folder"
    conf_dict["Enable Error Message"] = conf[7]
    conf_dict["Error Message"] = conf[8]
    conf_dict["Disable Firewall"] = conf[9]
    #conf_dict[""] = conf[10]
    #conf_dict[""] = conf[11]
    conf_dict["USB Spread"] = conf[12]
    conf_dict["MSN Spread"] = conf[13]
    conf_dict["P2P Spread"] = conf[14]
    conf_dict["Melt"] = conf[15]
    conf_dict["Get Default User Name"] = conf[16]
    conf_dict["Connection Delay"] = conf[17]
    conf_dict["Set Hidden"] = conf[18]
    conf_dict["Protect Process"] = conf[19]
    #conf_dict[""] = conf[20]

    return conf_dict
    
def v801(conf):
    conf_dict = {}
    conf_dict["Domain"] = DecryptRC4("UniQue OussamiO", conf[1])
    conf_dict["Campaign"] = conf[2]
    conf_dict["Enable Startup"] = conf[3]
    conf_dict["StartupName"] = conf[4]
    conf_dict["FolderName"] = conf[5]
    if conf[6] == "D":
        conf_dict["Path"] = "App Data Folder"
    elif conf[6] == "W":
        conf_dict["Path"] = "Windows Folder"
    if conf[6] == "s":
        conf_dict["Path"] = "System Folder"
    conf_dict["Enable Error Message"] = conf[7]
    conf_dict["Error Message"] = conf[8]
    conf_dict["Disable Firewall"] = conf[9]
    #conf_dict[""] = conf[10]
    #conf_dict[""] = conf[11]
    conf_dict["USB Spread"] = conf[12]
    conf_dict["MSN Spread"] = conf[13]
    conf_dict["P2P Spread"] = conf[14]
    conf_dict["Melt"] = conf[15]
    conf_dict["Get Default User Name"] = conf[16]
    conf_dict["Connection Delay"] = conf[17]
    conf_dict["Set Hidden"] = conf[18]
    conf_dict["Protect Process"] = conf[19]
    conf_dict["Name To Spread"] = conf[20]
    conf_dict["Enable Active X"] = conf[21]
    conf_dict["Active X Key"] = conf[22]
    conf_dict["Enable Mutex"] = conf[23]
    conf_dict["Mutex"] = conf[24]
    conf_dict["Persistant Server"] = conf[25]
    conf_dict["Offline Keylogger"] = conf[26]
    conf_dict["Disable Task Manager"] = conf[27]
    conf_dict["Disable RegEdit"] = conf[28]
    return conf_dict


class LostDoorDump(Signature):
    name = "lostdoor_dump"
    description = "LostDoor RAT has been indentified (config has been dumped)"
    severity = 5
    categories = ["malware", "rat"]
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"

    def on_yara(self, category, filepath, match):
        if match.name != "LostDoor":
            return

        cfg = None
        try:
            cfg = config(open(filepath, 'rb').read())
        except Exception as e:
            traceback.print_exc()
            pass

        if not cfg:
            return

        cfg["family"] = "LostDoor RAT"
        cfg["cnc"] = cfg["Domain"]
        if "Mutex"in cfg:
            cfg["type"] = cfg["Mutex"]
        self.mark_config(cfg)
        return True
