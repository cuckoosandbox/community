# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class PowershellDdiRc4(Signature):
    name = "powershell_ddi_rc4"
    description = "Powershell downloads RC4 crypted data and executes it"
    severity = 5
    categories = ["script", "dropper", "downloader", "malware", "powershell"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"

    def on_yara(self, category, filepath, match):
        if match.name != "PowershellDdiRc4":
            return

        host = match.string("Host", 0)
        path = match.string("Path", 0).strip("'")
        key = match.string("Key", 0)

        if "'" in key:
            key = key.split("'")[1]
        if '"' in key:
            key = key.split('"')[1]

        self.mark_config({
            "family": "Powershell DDI RC4 (downloader)",
            "url": "%s%s" % (host, path),
            "key": key,
        })
        return True
