# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import shlex
import yara
import logging
import traceback
import re

from lib.cuckoo.common.abstracts import Signature
from cuckoo.misc import cwd

log = logging.getLogger()

class PowershellDI(Signature):
    name = "powershell_di"
    description = "Powershell script has download & invoke calls"
    severity = 1
    categories = ["script", "dropper", "downloader", "malware", "powershell"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        _rule = """
        rule PowershellDI {
          meta:
            author = "FDD"
            description = "Extract Download/Invoke calls from powershell script"

          strings:
            $d1 = /downloaddata\([^)]+\)/ nocase
            $d2 = /downloadstring\([^)]+\)/ nocase
            $d3 = /downloadfile\([^)]+\)/ nocase
            $i1 = /invoke[^;]*/ nocase
            $i2 = /iex[^;]*/ nocase

          condition:
            any of ($d*) and any of ($i*)
        }
        """
        for cmdline in self.get_command_lines():
            lower = cmdline.lower()

            if "powershell" not in lower:
                continue

            cmdpattern = re.compile("\-[e^]{1,2}[ncodema^]+")
            if cmdpattern.search(lower):
                script, args = None, shlex.split(cmdline)
                for idx, arg in enumerate(args):
                    if "-enc" not in arg.lower() and "-encodedcommand" not in arg.lower():
                        continue

                    try:
                        script = args[idx+1].decode("base64").decode("utf16")
                        rule = yara.compile(cwd("yara", "scripts", "powershell_di.yar"))
                        matches = rule.match(data=script)

                        if matches:
                            for m in matches:
                                for string in m.strings:
                                    self.mark_ioc("Call", string[2])
                            break
                    except Exception as e:
                        traceback.print_exc(e)
                        pass

        return self.has_marks()
