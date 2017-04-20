# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import shlex
import yara
import logging
import traceback
import re

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger()

class PowershellMeterpreter(Signature):
    name = "powershell_meterpreter"
    description = "Meterpreter execution throught Powershell detected"
    severity = 5
    categories = ["script", "meterpreter", "powershell", "malware"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        psmeterpreter_rule = """
        rule PowershellMeterpreter {
          meta:
            author = "FDD"
            description = "Rule for Powershell DFSP detection"

          strings:
            $Net = "New-Object Net.WebClient" nocase
            $Download = "downloadstring(" nocase
            $Start = "Invoke-Shellcode" nocase
            $Iex = "iex" nocase
            $Package = /windows\/meterpreter\/[\w_]+/
            $Host = /Lhost\s+[^\s]+/
            $Port = /Lport\s+[^\s]+/

          condition:
            all of them
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
                        script = args[idx+1].decode("base64").decode("utf16").encode("utf8")
                        rule = yara.compile(source=psmeterpreter_rule)
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
