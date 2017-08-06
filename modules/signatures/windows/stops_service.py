# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from lib.cuckoo.common.abstracts import Signature

class StopsService(Signature):
    name = "stops_service"
    description = "Stops Windows services"
    severity = 3
    categories = ["anti-av"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    indicator = (
        "HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\ControlSet001\\\\services\\\\(.*)\\\\Start"
    )

    def on_complete(self):
        for regkey in self.check_key(pattern=self.indicator, regex=True, actions=["regkey_written"], all=True):
            x = re.match(self.indicator, regkey, re.I)
            self.mark_ioc("service", "%s (regkey %s)" % (x.group(1), regkey))
            self.severity += 1

        for cmdline in self.get_command_lines():
            if "sc stop" in cmdline.lower() or "sc.exe stop" in cmdline.lower():
                self.severity += 1
                self.mark_ioc("cmdline", cmdline)  

        self.severity = min(self.severity, 5)
        return self.has_marks()
