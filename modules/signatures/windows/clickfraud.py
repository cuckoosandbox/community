# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com), Updated 2017 for cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class ClickfraudCookies(Signature):
    name = "clickfraud_cookies"
    description = "Overrides system cookie policy, indicative of click fraud"
    severity = 3
    categories = ["clickfraud"]
    authors = ["Optiv"]
    minimum = "2.0"

    filter_apinames = "InternetSetOptionA"

    def on_call(self, call, process):
        if call["flags"]["option"] == "INTERNET_SUPPRESS_COOKIE_POLICY":
            self.mark_call()

    def on_complete(self):
        return self.has_marks()
