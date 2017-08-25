# Copyright (C)  2014 Optiv, Inc. (brad.spengler@optiv.com), Updated 2016 for cuckoo 2.0 
# Updated 2017 by Andreas Nobel - add support for SRPv2 aka Applocker
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AntiAVSRP(Signature):
    name = "antiav_srp"
    description = "Modifies Applocker (SRPv2) or Software Restriction Policies likely to cripple AV"
    severity = 3
    categories = ["anti-av"]
    authors = ["Optiv and Andreas Nobel"]
    minimum = "2.0"

    regkeys_re_srp_list = [
        ".*\\\\Policies\\\\Microsoft\\\\Windows\\\\SrpV2\\\\\\.*",
        ".*\\\\Policies\\\\Microsoft\\\\Windows\\\\Safer\\\\\CodeIdentifiers\\\\.*"
    ]


    def on_complete(self):
        for indicator in self.regkeys_re_srp_list:
            for regkey in self.check_key(pattern=indicator, regex=True, actions=["regkey_written"], all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()

