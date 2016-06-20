# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import shlex

from lib.cuckoo.common.abstracts import Signature

class SuspiciousPowershell(Signature):
    name = "suspicious_powershell"
    description = "Creates a suspicious Powershell process"
    severity = 3
    categories = ["script", "dropper", "downloader", "packer"]
    authors = ["Kevin Ross", "Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        for cmdline in self.get_command_lines():
            lower = cmdline.lower()

            if "powershell" not in lower:
                continue

            if "-ep bypass" in lower or "-executionpolicy bypass" in lower or "-ep unrestricted" in lower or "-executionpolicy unrestricted" in lower or "YnlwYXNz" in lower or "J5cGFzc" in lower or "ieXBhc3" in lower or "dW5yZXN0cmljdGVk" in lower or "VucmVzdHJpY3RlZ" in lower or "1bnJlc3RyaWN0ZW" in lower:
                self.mark(cmdline=cmdline, value="Attempts to bypass execution policy")

            if "-nop" in lower or "-noprofile" in lower:
                self.mark(cmdline=cmdline, value="Does not load current user profile")

            if "-w hidden" in lower or "-windowstyle hidden" in lower:
                self.mark(cmdline=cmdline, value="Attempts to execute command with a hidden window")

            if "downloadfile(" in lower or "ZG93bmxvYWRmaWxlK" in lower or "Rvd25sb2FkZmlsZS" in lower or "kb3dubG9hZGZpbGUo" in lower:
                self.mark(cmdline=cmdline, value="Uses powershell to execute a file download from the command line")

            if "-enc" in lower or "-e " in lower:
                # This has to be improved.
                script, args = None, shlex.split(cmdline)
                for idx, arg in enumerate(args):
                    if "-enc" not in arg.lower() and "-e " not in arg.lower():
                        continue

                    try:
                        script = args[idx+1].decode("base64").decode("utf16")
                        break
                    except:
                        pass

                self.mark(cmdline=cmdline, value="Uses a base64 encoded command value",
                          script=script)

        return self.has_marks()
