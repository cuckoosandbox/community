# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import traceback
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

def is_valid_config(config):
    if config[:3] != "\x0c\x0c\x0c":
        return False
    if config.count("\x0C\x0C\x0C") < 15:
        return False
    return True


def get_next_rng_value():
    global prng_seed
    prng_seed = ((prng_seed * 1140671485 + 12820163) & 0xffffff)
    return prng_seed / 65536

def decrypt_configuration(hex):
    global prng_seed
    if not hex:
        return None

    ascii = hex.decode('hex')
    tail = ascii[0x20:]

    pre_check = []
    for x in xrange(3):
        pre_check.append(ord(tail[x]) ^ 0x0c)

    for x in xrange(0xffffff):
        prng_seed = x
        if get_next_rng_value() != pre_check[0] or get_next_rng_value() != pre_check[1] or get_next_rng_value() != pre_check[2]:
            continue
        prng_seed = x
        config = "".join((chr(ord(c) ^ int(get_next_rng_value())) for c in tail))
        if is_valid_config(config):
            return config.split("\x0c\x0c\x0c")
    return None
 

def config_extract(raw_data):
    config_pattern = re.findall('[0-9a-fA-F]{154,}', raw_data)
    for s in config_pattern:
        if (len(s) % 2) == 1:
            s = s[:-1]
            return s

def config_parser(config):
    config_dict = {}
    config_dict['Domain'] = config[1]
    config_dict['Client Control Port'] = config[2]
    config_dict['Client Transfer Port'] = config[3]
    config_dict['Campaign ID'] = config[4]
    config_dict['File Name'] = config[5]
    config_dict['Install Path'] = config[6]
    config_dict['Registry Key'] = config[7]
    config_dict['ActiveX Key'] = config[8]
    config_dict['Install Flag'] = config[9]
    config_dict['Hide File'] = config[10]
    config_dict['Melt File'] = config[11]
    config_dict['Delay'] = config[12]
    config_dict['USB Spread'] = config[13]
    config_dict['Mutex'] = config[14]
    config_dict['Log File'] = config[15]
    config_dict['Folder Name'] = config[16]
    config_dict['Smart DNS'] = config[17]
    config_dict['Protect Process'] = config[18]
    return config_dict
        
def config(data):
    raw_config = config_extract(data)
    config = decrypt_configuration(raw_config)
    if config is not None and len(config) > 15:
        sorted_config = config_parser(config)
        return sorted_config
    return None


class BlackShadesDump(Signature):
    name = "blackshades_dump"
    description = "Black Shades RAT has been indentified (config has been dumped)"
    severity = 5
    categories = ["malware", "rat"]
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"

    def on_yara(self, category, filepath, match):
        if match.name != "BlackShades":
            return

        cfg = None
        try:
            cfg = config(open(filepath, 'rb').read())
        except Exception as e:
            traceback.print_exc()
            pass

        if not cfg:
            return

        cfg["family"] = "BlackShades RAT"
        cfg["cnc"] = cfg["Domain"]
        cfg["type"] = cfg["Mutex"]
        self.mark_config(cfg)
        return True
