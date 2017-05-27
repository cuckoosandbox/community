# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class PowershellUnicorn(Signature):
    name = "powershell_unicorn"
    description = "A Powershell script generated using the unicorn technique (shellcode injection in powershell process) has been detected"
    severity = 5
    categories = ["script", "dropper", "downloader", "malware"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"

    def on_yara(self, category, filepath, match):
        if match.name != "UnicornGen":
            return

        self.mark_config({
            "family": "Unicorn by trustedsec.com",
        })
        return True
