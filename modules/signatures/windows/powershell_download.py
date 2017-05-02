# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class PowershellDownload(Signature):
    name = "powershell_download"
    description = "URL downloaded by powershell script"
    severity = 2
    categories = ["downloader"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = [
        "recv",
    ]

    def on_call(self, call, process):
        if (process["process_name"].lower() == "powershell.exe" and
            call["arguments"]["buffer"] != ""):
            self.mark_ioc("Data received", call["arguments"]["buffer"])

    def on_complete(self):
        return self.has_marks()
