# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class PowershellDI(Signature):
    name = "powershell_di"
    description = "Powershell script has download & invoke calls"
    severity = 1
    categories = ["script", "dropper", "downloader", "malware", "powershell"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"

    def on_yara(self, category, filepath, match):
        if match.name != "PowershellDI":
            return

        if "d1" in match.offsets:
            url = match.string("d1", 0)
        if "d2" in match.offsets:
            url = match.string("d2", 0)
        if "d3" in match.offsets:
            url = match.string("d3", 0)

        if url.count('"') == 2:
            url = url.split('"')[1]
        elif url.count("'") == 2:
            url = url.split("'")[1]
        else:
            url = None

        if url:
            self.mark_config({
                "family": "Powershell Download & Invoke",
                "url": url,
            })
            return True
