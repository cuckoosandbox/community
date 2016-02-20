# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from lib.cuckoo.common.abstracts import Signature

class SuspiciousJavascript(Signature):
    name = "js_suspicious"
    description = "Suspicious Javascript actions"
    severity = 3
    categories = ["unpacking"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "COleScript_Compile",

    js_re = [
        "eval\\(\\s*eval\\(",
        "eval\\(\\s*\\['\"]\\s*String\\.fromCharCode",
        "^\\s*String\\.fromCharCode\\((?:[0-9a-fA-F,\\s]+)\\)\\s*$",
        "\\s*document\\.location\\.href\\s*=\\s*['\"].*['\"];$",
        "malware\\.dontneedcoffee\\.com",
    ]

    def on_call(self, call, process):
        for regex in self.js_re:
            if re.search(regex, call["arguments"]["script"], re.S):
                self.mark_call()
                break

        return self.has_marks()
