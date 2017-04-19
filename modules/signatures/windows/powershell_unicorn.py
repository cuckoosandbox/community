# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import shlex
import yara
import logging
import traceback

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger()

class PowershellUnicorn(Signature):
    name = "powershell_unicorn"
    description = "A Powershell script generated using the unicorn technique (shellcode injection in powershell process) has been detected"
    severity = 5
    categories = ["script", "dropper", "downloader", "malware"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        unicorngen_rule = """
        rule UnicornGen {
          meta:
            author = "FDD @ Cuckoo Sandbox"
            description = "Rule for malcode generated with the Unicorn tool"
            ref = "https://github.com/trustedsec/unicorn"

          strings:
            $Import = "DllImport" nocase
            $Kernel32 = "kernel32.dll"
            $msvcrt = "msvcrt.dll"
            $fn1 = "VirtualAlloc"
            $fn2 = "CreateThread"
            $fn3 = "memset"
            $Shellcode = /=\s*((0x)?[0-9A-F]{2}\s*[,;]\s*)+/ nocase

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
                        rule = yara.compile(source=unicorngen_rule)
                        matches = rule.match(data=script)

                        if matches:
                            self.mark_ioc("Malware family", "Unicorn generated script")
														self.mark_ioc("Tool referece", "https://github.com/trustedsec/unicorn")
                            for m in matches:
                                for string in m.strings:
                                    if string[1] == "$Shellcode":
                                        self.mark_ioc("Shellcode", string[2])
                            break
                    except Exception as e:
                        traceback.print_exc(e)
                        pass

        return self.has_marks()
