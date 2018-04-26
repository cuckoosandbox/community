# Copyright (C) 2014 Optiv Inc. (brad.spengler@optiv.com)
# Copyright (C) 2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class CreatesNullRegistryEntry(Signature):
    name = "creates_null_reg_entry"
    description = "Creates a registry value with a null byte to avoid detection"
    authors = ["Cuckoo Technologies"]
    severity = 2
    categories = ["stealth"]
    minimum = "2.0"

    filter_apinames = (
        "NtSetValueKey", "NtCreateKey", "RegCreateKeyExA",
        "RegCreateKeyExW", "RegSetValueExA", "RegSetValueExW",
    )

    def on_call(self, call, process):
        api = call["api"]
        arg = call["arguments"]
        regkey = arg["regkey"]
        null_byte = "\\x00"
        regkey_r = ""
        value = ""
        if "SetValue" in api:
            regvalue = arg["value"]
            if not isinstance(regvalue, (str, unicode)):
                regvalue = str(regvalue)
            regvalue = regvalue.encode('utf-8')
            if regvalue.startswith(null_byte):
                self.mark_call()
        if "RegSetValue" in api:
            regkey_r = arg["regkey_r"]
            if not isinstance(regkey_r, (str, unicode)):
                regvalue = str(regkey_r)
            regkey_r = regkey_r.encode('utf-8')
        else:
            regkey_r = str(regkey).split("\\")[-1]
        if regkey_r.startswith(null_byte):
            self.mark_call()
        return self.has_marks()
