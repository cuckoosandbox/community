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

class PowershellMeterpreter(Signature):
    name = "powershell_meterpreter"
    description = "Meterpreter execution throught Powershell detected"
    severity = 5
    categories = ["script", "meterpreter", "powershell", "malware"]
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
                    if not cmdpattern.search(arg.lower()):
                        continue

                    try:
                        script = args[idx+1].decode("base64").decode("utf16").encode("utf8")
                        rule = yara.compile(cwd("yara", "scripts", "powershell_meterpreter.yar"))
                        matches = rule.match(data=script)

                        if matches:
                            for m in matches:
                                for string in m.strings:
                                    if (string[1] == "$Host" or string[1] == "$Port" or
                                        string[1] == "$Package"):
                                        self.mark_ioc(string[1][1:], string[2])
                            break
                    except Exception as e:
                        traceback.print_exc(e)
                        pass

        return self.has_marks()
