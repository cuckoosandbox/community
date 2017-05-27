# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class PowershellCcDns(Signature):
    name = "powershell_c2dns"
    description = "Powershell C&C bot through DNS detected"
    severity = 5
    categories = ["script", "bot", "dns", "malware"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"

    def on_yara(self, category, filepath, match):
        if match.name != "PowershellCcDns":
            return

        dns = match.string("DNS", 0).replace("nslookup -q=txt", "").strip()
        self.mark_config({
            "family": "Powershell DNS TXT Dropper",
            "url": dns,
        })
        return True
