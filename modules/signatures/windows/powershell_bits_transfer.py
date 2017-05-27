# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class PowershellBitsTransfer(Signature):
    name = "powershell_bitstransfer"
    description = "Powershell BITS Transfer detected (dropper malware)"
    severity = 5
    categories = ["script", "dropper", "downloader", "malware", "powershell"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"

    def on_yara(self, category, filepath, match):
        if match.name != "PowershellBitsTransfer":
            return

        self.mark_config({
            "family": "Powershell BITS Transfer Dropper",
            "url": match.string("Payload", 0),
        })
        return True
