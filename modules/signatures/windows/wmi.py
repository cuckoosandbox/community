# Copyright (C) 2010-2015 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from lib.cuckoo.common.abstracts import Signature

class HasWMI(Signature):
    name = "has_wmi"
    description = "Executes one or more WMI queries"
    severity = 2

    blacklist = "(AntivirusProduct|FirewallProduct)"

    def on_complete(self):
        for query in self.get_wmi_queries():
            self.mark_ioc("wmi", query)

            if re.search(self.blacklist, query, re.I):
                self.severity = 3

        return self.has_marks()
