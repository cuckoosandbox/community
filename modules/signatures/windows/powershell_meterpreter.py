# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class PowershellMeterpreter(Signature):
    name = "powershell_meterpreter"
    description = "Meterpreter execution throught Powershell detected"
    severity = 5
    categories = ["script", "meterpreter", "powershell", "malware"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"

    def on_yara(self, category, filepath, match):
        if match.name != "PowershellMeterpreter":
            return

        host = match.string("Host", 0).split()[1]
        port = match.string("Port", 0).split()[1]
        package = match.string("Package", 0)

        self.mark_config({
            "family": "Powershell Meterpreter",
            "url": "tcp://%s:%s" % (host, port),
            "type": package,
        })
        return True
