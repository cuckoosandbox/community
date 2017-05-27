# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AmsiBypass(Signature):
    name = "amsi_bypass"
    description = "Powershell script bypasses AMSI (Antimalware Scan Interface) by reporting a failure in AMSI initialization"
    severity = 5
    categories = ["script", "malware", "powershell", "amsi"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"

    def on_yara(self, category, filepath, match):
        if match.name != "PowershellAMSI":
            return

        self.mark_ioc("function", match.string("fn1", 0))
        self.mark_ioc("function", match.string("fn2", 0))
        self.mark_ioc("function", match.string("fn3", 0))
        return True
