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

class AmsiBypass(Signature):
    name = "amsi_bypass"
    description = "Powershell script bypasses AMSI (Antimalware Scan Interface) by reporting a failure in AMSI initialization"
    severity = 5
    categories = ["script", "malware", "powershell", "amsi"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
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
                        rule = yara.compile(cwd("yara", "scripts", "powershell_AMSI.yar"))
                        matches = rule.match(data=script)

                        if matches:
                            for m in matches:
                                fn = re.compile("fn[0-9]")
                                for string in m.strings:
                                    if fn.search(string[1]):
                                        self.mark_ioc("Function", string[2])
                            return True

                    except Exception as e:
                        traceback.print_exc(e)
                        pass

        return self.has_marks()
