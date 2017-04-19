# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import shlex
import yara
import logging
import traceback

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger()

class PowershellBitsTransfer(Signature):
    name = "powershell_bitstransfer"
    description = "Powershell BITS Transfer detected (dropper malware)"
    severity = 5
    categories = ["script", "dropper", "downloader", "malware", "powershell"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        bits_rule = """
        rule PowershellBitsTransfer {
          meta:
            author = "FDD @ Cuckoo Sandbox"
            description = "Rule for Powershell BITS Transfer detection"

          strings:
            $Module = "Import-Module BitsTransfer" nocase
            $Download = "Start-BitsTransfer" nocase
            $Start = "Invoke-Item" nocase
            $Payload = /(https?|ftp):\/\/[^\s\/$.?#].[^\s"']*/

          condition:
            all of them
        }
        """
        for cmdline in self.get_command_lines():
            lower = cmdline.lower()

            if "powershell" not in lower:
                continue

            if "-enc" in lower or "-encodedcommand" in lower:
                script, args = None, shlex.split(cmdline)
                for idx, arg in enumerate(args):
                    if "-enc" not in arg.lower() and "-encodedcommand" not in arg.lower():
                        continue

                    try:
                        script = args[idx+1].decode("base64").decode("utf16")
                        rule = yara.compile(source=bits_rule)
                        matches = rule.match(data=script)

                        if matches:
                            self.mark_ioc("Malware family", "Powershell BITS Transfer dropper")
                            for m in matches:
                                for string in m.strings:
                                    if string[1] == "$Payload":
                                        self.mark_ioc("Payload", string[2])
                            break
                    except Exception as e:
                        traceback.print_exc(e)
                        pass

        return self.has_marks()
