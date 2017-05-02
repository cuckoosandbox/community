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

class PowershellDdiRc4(Signature):
    name = "powershell_ddi_rc4"
    description = "Powershell downloads RC4 crypted data and executes it"
    severity = 5
    categories = ["script", "dropper", "downloader", "malware", "powershell"]
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
                        script = args[idx+1].decode("base64").decode("utf16")
                        rule = yara.compile(cwd("yara", "scripts", "powershell_ddi_rc4.yar"))
                        matches = rule.match(data=script)

                        if matches:
                            self.mark_ioc("Malware family", "Powershell DDI RC4 (downloader)")
                            for m in matches:
                                for string in m.strings:
                                    if string[1] == "$Host" or string[1] == "$Path":
                                        self.mark_ioc(string[1][1:], string[2])
                                    elif string[1] == "$Key":
                                        argre = re.compile("['\"]([^'\"]+)['\"]")
                                        key = argre.search(string[2]).group(1)
                                        self.mark_ioc(string[1][1:], key)
                            break
                    except Exception as e:
                        traceback.print_exc(e)
                        pass

        return self.has_marks()
