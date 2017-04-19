# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import shlex
import yara
import logging
import traceback
import re
import zlib

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger()

class Powerfun(Signature):
    name = "powerfun"
    description = "The Powerfun powershell script has been detected (shellcode injector)"
    severity = 5
    categories = ["script", "malware", "injector"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        powerfun_rule = """
        rule Powerfun {
          meta:
            author = "FDD @ Cuckoo Sandbox"
            description = "Rule for the Powefun shellcode injector"

          strings:
            $obj1 = "New-Object System.Diagnostics.ProcessStartInfo" nocase
            $fn1 = "IEX" nocase
            $fn2 = "IO.Compression.GzipStream" nocase
            $fn3 = "[System.Diagnostics.Process]::Start" nocase
            $fn4 = "::Decompress" nocase
            $Shellcode = /FromBase64String\(['"]+[\w=\/\+]+['"]+\)/ nocase

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
                        rule = yara.compile(source=powerfun_rule)
                        matches = rule.match(data=script)

                        if matches:
                            self.mark_ioc("Malware family", "Powerfun injector")
                            for m in matches:
                                for string in m.strings:
                                    if string[1] == "$Shellcode":
                                        b64 = (re.search("\(['\"]+([\w=\/\+]+)['\"]+\)", string[2])
                                                 .group(1))
                                        compressed = bytes(b64.decode("base64"))
                                        shellcode = zlib.decompress(compressed, 15+32)
                                        self.mark_ioc("Invoked script", shellcode)
                            break
                    except Exception as e:
                        traceback.print_exc(e)
                        pass

        return self.has_marks()
