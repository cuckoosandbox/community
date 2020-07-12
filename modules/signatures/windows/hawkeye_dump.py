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
from struct import unpack

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger(__name__) 

def config(data):
        pe = pype32.PE(data=data)
        string_list = get_strings(pe, 2)

        # identify the version
        if 'InvisibleSoft' in string_list:
            key, salt = 'InvisibleSoft', '3000390039007500370038003700390037003800370038003600'.decode('hex')
            config_dict = config_2(key, salt, string_list)
        else:
            key, salt = 'HawkEyeKeylogger', '3000390039007500370038003700390037003800370038003600'.decode('hex')
            config_dict = config_1(key, salt, string_list)
        return config_dict

#Helper Functions Go Here

def string_clean(line):
    return ''.join((char for char in line if 32< ord(char) < 127))
    
# Crypto Stuffs
def decrypt_string(key, salt, coded):
    #try:
        # Derive key
        generator = PBKDF2(key, salt)
        aes_iv = generator.read(16)
        aes_key = generator.read(32)
        # Crypto
        mode = AES.MODE_CBC
        cipher = AES.new(aes_key, mode, IV=aes_iv)
        value = cipher.decrypt(b64decode(coded)).replace('\x00', '')
        return value#.encode('hex')
    #except:
        #return False

def des_decrypt(key, data):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.decrypt(data)

# Get a list of strings from a section
def get_strings(pe, dir_type):
    counter = 0
    string_list = []
    m = pe.ntHeaders.optionalHeader.dataDirectory[14].info
    for s in m.netMetaDataStreams[dir_type].info:
        for offset, value in s.iteritems():
            string_list.append(value)
        counter += 1
    return string_list
        
#Turn the strings in to a python config_dict

# Duplicate strings dont seem to be duplicated so we need to catch them
def config_1(key, salt, string_list):
    config_dict = {}
    for i in range(40):
        if len(string_list[1]) > 200:
            config_dict["Embedded File found at {0}".format(i)]
        else:
            try:
                config_dict["Crypted String {0}".format(i)] = decrypt_string(key, salt, string_list[i])
            except:
                config_dict["Config String {0}".format(i)] = string_list[i]
    return config_dict

def config_2(key, salt, string_list):
    config_dict = {}
    # Derive the key from the password
    hash_key = '957B38037395359C'[8:]

    # Get offset for our settings
    offset = string_list.index('ProductID')
    config_dict['Email User'] = decrypt_string(key, salt, string_list[offset + 2])
    config_dict['Email Password'] = decrypt_string(key, salt, string_list[offset + 3])
    config_dict['SMTP'] = decrypt_string(key, salt, string_list[offset + 4])
    config_dict['SMTP Port'] = string_list[offset + 5]
    config_dict['Interval'] = string_list[offset + 6]
    config_dict['MsgBox Title'] = string_list[offset + 7]
    config_dict['MsgBox Text'] = string_list[offset + 8]
    config_dict['MsgBox Holder'] = string_list[offset + 9]
    config_dict['FTP Host'] = decrypt_string(key, salt, string_list[offset + 10])
    config_dict['FTP User'] = decrypt_string(key, salt, string_list[offset + 11])
    config_dict['FTP Pass'] = decrypt_string(key, salt, string_list[offset + 12])
    config_dict['Use Email'] = string_list[offset + 13]
    config_dict['Use FTP'] = string_list[offset + 14]
    config_dict['Delay Execution'] = string_list[offset + 15]
    config_dict['IE Clear'] = string_list[offset + 16]
    config_dict['Firefox Clear'] = string_list[offset + 17]
    config_dict['Steam Clear'] = string_list[offset + 18]
    config_dict['Chrome Clear'] = string_list[offset + 19]
    config_dict['Binder'] = string_list[offset + 20]
    config_dict['Downloader'] = string_list[offset + 21]
    config_dict['Visit Website'] = string_list[offset + 22]
    config_dict['Block Website'] = string_list[offset + 23]
    config_dict['Execution'] = string_list[offset + 24]
    config_dict['SSL'] = string_list[offset + 25]
    config_dict['Fake Error'] = string_list[offset + 26]
    config_dict['Startup'] = string_list[offset + 27]
    config_dict['Screeny'] = string_list[offset + 28]
    config_dict['ClipBoard'] = string_list[offset + 29]
    config_dict['TaskManager'] = string_list[offset + 30]
    config_dict['KeyStroke'] = string_list[offset + 31]
    config_dict['Stealer'] = string_list[offset + 32]
    config_dict['Melt'] = string_list[offset + 33]
    config_dict['Registry'] = string_list[offset + 34]
    config_dict['CMD'] = string_list[offset + 35]
    config_dict['MSConfig'] = string_list[offset + 36]
    config_dict['Spreaders'] = string_list[offset + 37]
    config_dict['Install Name'] = '%APPDATA%\{0}'.format(string_list[offset + 38])
    return config_dict

class HawkEyeDump(Signature):
    name = "hawkeye_dump"
    description = "HawkEye RAT has been indentified (config has been dumped)"
    severity = 5
    categories = ["malware", "rat"]
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"

    def on_yara(self, category, filepath, match):
        if match.name != "HawkEye":
            return

        cfg = None
        try:
            cfg = config(open(filepath, 'rb').read())
        except Exception as e:
            traceback.print_exc()
            pass

        if not cfg:
            return

        cfg["family"] = "HawkEye RAT"
        cfg["cnc"] = cfg["Email User"]
        self.mark_config(cfg)
        return True
