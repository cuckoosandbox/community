# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import traceback
import yara
import re
import hashlib
from base64 import b64decode
from Crypto.Cipher import AES

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger(__name__) 

def config(raw_data):
    try:
        re_pattern = '[a-zA-Z0-9+/]{60,}={0,2}'
        conf_string = re.findall(re_pattern, raw_data)[0]
        decoded = decrypt_string('Specify a Password', conf_string)
        config_dict = parse_config(decoded.split('|'))    
    except Exception as e:
        return False
    return config_dict
        
#Helper Functions Go Here
def decrypt_string(key_string, coded):
    try:
        # Derive key
        key_hash = hashlib.md5(key_string).hexdigest()
        aes_key = key_hash[:30]+key_hash+'00'
        #Crypto
        cipher = AES.new(aes_key.decode('hex'))
        value = cipher.decrypt(b64decode(coded))
        return value
    except:
        traceback.print_exc()
        return False
    
#Turn the strings in to a python config_dict
def parse_config(string_list):
    config_dict = {}
    config_dict["Domain"] = string_list[0]
    config_dict["Port"] = string_list[1]
    config_dict["BackUp Domain"] = string_list[2]
    config_dict["Install Name"] = string_list[3]
    config_dict["Startup Name"] = string_list[4]
    config_dict["Campaign ID"] = string_list[5]
    return config_dict

class LuminosityLinkDump(Signature):
    name = "luminositylink_dump"
    description = "LuminosityLink RAT has been indentified (config has been dumped)"
    severity = 5
    categories = ["malware", "rat"]
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"

    def on_yara(self, category, filepath, match):
        if match.name != "LuminosityLink":
            return

        cfg = None
        try:
            cfg = config(open(filepath, 'rb').read())
        except Exception as e:
            traceback.print_exc()
            pass

        if not cfg:
            return

        cfg["family"] = "LuminosityLink RAT"
        cfg["cnc"] = cfg["Domain"]
        cfg["type"] = cfg["Campaign ID"]
        self.mark_config(cfg)
        return True
