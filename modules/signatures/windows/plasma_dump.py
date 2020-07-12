# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import traceback
import yara
import re
import string
import hashlib
from base64 import b64decode
from Crypto.Cipher import AES
from struct import unpack

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger(__name__) 

def config(raw_data):
    try:
        re_pattern = '[a-zA-Z0-9+/]{60,}={0,2}'
        conf_string = re.findall(re_pattern, raw_data)[0]
        decoded = decrypt_string('IUWEEQWIOER$89^*(&@^$*&#@$HAFKJHDAKJSFHjd89379327AJHFD*&#($hajklshdf##*$&^(AAA', conf_string)
        config_dict = parse_config(decoded.split('*'))
        return config_dict
            
    except Exception as e:
        traceback.print_exc()
        return False
        
        
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
        return False
    
def parse_config(string_list):
    config_dict = {}
    config_dict["Domain"] = string_list[1]
    config_dict["Port"] = string_list[2]
    config_dict["Username"] = string_list[3]
    config_dict["Install Name"] = string_list[4]
    config_dict["Install Path"] = string_list[5]
    config_dict["settings"] = string_list[6]      
    config_dict["BackUp Domain"] = string_list[7]
    return config_dict

class PlasmaDump(Signature):
    name = "plasma_dump"
    description = "Plasma RAT has been indentified (config has been dumped)"
    severity = 5
    categories = ["malware", "rat"]
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"

    def on_yara(self, category, filepath, match):
        if match.name != "Plasma":
            return

        cfg = None
        try:
            cfg = config(open(filepath, 'rb').read())
        except Exception as e:
            traceback.print_exc()
            pass

        if not cfg:
            return

        cfg["family"] = "Plasma RAT"
        cfg["cnc"] = cfg["Domain"]
        self.mark_config(cfg)
        return True
