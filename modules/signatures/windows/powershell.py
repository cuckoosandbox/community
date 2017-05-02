# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import shlex
import re

from lib.cuckoo.common.abstracts import Signature

class SuspiciousPowershell(Signature):
    name = "suspicious_powershell"
    description = "Creates a suspicious Powershell process"
    severity = 3
    categories = ["script", "dropper", "downloader", "packer"]
    authors = ["Kevin Ross", "Cuckoo Technologies", "FDD"]
    minimum = "2.0"

    def on_complete(self):
        for cmdline in self.get_command_lines():
            lower = cmdline.lower()

            if "powershell" not in lower:
                continue

            epre = re.compile("\-[e^]{1,2}[xecution]*[p^]{0,2}[olicy]*[\s]+bypass")
            m = epre.search(lower)
            if m:
                self.mark(cmdline=cmdline, value="Attempts to bypass execution policy", option=m.group(0))

            epre = re.compile("\-[e^]{1,2}[xecution]*[p^]{0,2}[olicy]*[\s]+unrestricted")
            m = epre.search(lower)
            if m:
                self.mark(cmdline=cmdline, value="Attempts to bypass execution policy", option=m.group(0))

            nopre = re.compile("\-nop[rofile]*")
            m = nopre.search(lower)
            if m:
                self.mark(cmdline=cmdline, value="Does not load current user profile", option=m.group(0))

            nolre = re.compile("\-nol[og]*")
            m = nolre.search(lower)
            if m:
                self.mark(cmdline=cmdline, value="Hides the copyright banner when PowerShell launches", option=m.group(0))

            hiddenre = re.compile("\-[w^]{1,2}[indowstyle^]*[\s]+hidden")
            m = hiddenre.search(lower)
            if m:
                self.mark(cmdline=cmdline, value="Attempts to execute command with a hidden window", option=m.group(0))

            nonire = re.compile("\-noni[nteraciv]*")
            m = nonire.search(lower)
            if m:
                self.mark(cmdline=cmdline, value="Prevents creating an interactive prompt for the user", option=m.group(0))

            if "downloadfile(" in lower:
                self.mark(cmdline=cmdline, value="Uses powershell to execute a file download from the command line")

            encre = re.compile("\-[e^]{1,2}[ncodema^]+")
            if encre.search(lower):
                # This has to be improved.
                script, args = None, shlex.split(cmdline)
                for idx, arg in enumerate(args):
                    if not encre.search(arg):
                        continue

                    try:
                        script = args[idx+1].decode("base64").decode("utf16")
                        break
                    except:
                        pass

                self.mark(cmdline=cmdline, value="Uses a base64 encoded command value",
                          script=script)

        return self.has_marks()
