# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import shlex
import yara
import logging
import traceback

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger()

class Powerworm(Signature):
    name = "powerworm"
    description = "The Powerworm powershell script has been detected"
    severity = 5
    categories = ["script", "malware", "powershell", "worm"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        powerworm_rule = """
        rule PowerWorm {
            meta:
                author = "FDD @ Cuckoo Sandbox"
                description = "Rule for PowerWorm script detection"

            strings:
                /* .onion URL for payload */
                $payload = /(https?|ftp):\/\/[^\s\/$.?#].[^\s'"]*/
                $uuid = "(get-wmiobject Win32_ComputerSystemProduct).UUID" nocase
                $run = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
                $tor = "Bootstrapped 100%: Done."
                $socks = "socksParentProxy=localhost:"
                $proxy = "New-Object System.Net.WebProxy" nocase
                /* PowerWorm uses junk strings in between code to obfuscate it */
                $junk = /;('|")[^'"]+('|")/

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
                        rule = yara.compile(source=powerworm_rule)
                        matches = rule.match(data=script)

                        if matches:
                            self.mark_ioc("Malware family", "PowerWorm")
                            for m in matches:
                                for string in m.strings:
                                    if string[1] == "$payload":
                                        self.mark_ioc("Payload URL", string[2])
                            break
                        else:
                            log.debug('Yara does not match')
                    except Exception as e:
                        traceback.print_exc(e)
                        pass

        return self.has_marks()
