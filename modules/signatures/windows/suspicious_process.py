# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class CreatesSuspiciousProcess(Signature):
    name = "suspicious_process"
    description = "Creates a suspicious process"
    severity = 2
    categories = ["packer"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    processes = [
        "svchost", "powershell", "regsvr32", "bcdedit",
    ]

    def on_complete(self):
        for cmdline in self.get_command_lines():
            for process in self.processes:
                if process in cmdline.lower():
                    self.mark(cmdline=cmdline, process=process)

        return self.has_marks()
