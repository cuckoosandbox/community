# Copyright (C) 2010-2015 Cuckoo Foundation. 2016 Brad Spengler
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class EventvwrAbuse(Signature):
    name = "eventvwr_abuse"
    description = "Abuses eventvwr.exe to execute a process as high integrity (bypasses UAC)"
    severity = 3
    categories = ["abuse"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"
    filter_apinames = set(["RegSetValueExA", "RegSetValueExW", "NtSetValueKey"])

    regkeys = [
        "HKEY_CURRENT_USER\mscfile\shell\open\command\(Default)",
        "HKEY_CURRENT_USER\Software\Classes\mscfile\shell\open\command",
    ]
    
    def on_call(self, call, process):
        args = call["arguments"]

        if not "regkey" in args:
            return

        if args["regkey"] in self.regkeys:
            self.mark_call()

    def on_complete(self):
        return self.has_marks()
