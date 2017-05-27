# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class PowershellDFSP(Signature):
    name = "powershell_dfsp"
    description = "Powershell Downloader DFSP detected"
    severity = 5
    categories = ["script", "dropper", "downloader", "malware"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"

    def on_yara(self, category, filepath, match):
        if match.name != "PowershellDFSP":
            return

        self.mark_config({
            "family": "Powershell Downloader DFSP",
            "url": match.string("Payload", 0),
        })
        return True
