# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class PowershellRequest(Signature):
    name = "powershell_request"
    description = "Poweshell is sending data to a remote host"
    severity = 2
    categories = ["downloader"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = [
        "send",
    ]

    def on_call(self, call, process):
        if process["process_name"].lower() == "powershell.exe":
            self.mark_ioc("Data sent", call["arguments"]["buffer"])

    def on_complete(self):
        return self.has_marks()
