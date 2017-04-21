# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import shlex
import yara
import logging
import traceback

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger()

class PowershellScheduler(Signature):
    name = "powershell_scheduler"
    description = "Powershell Scheduler (fake update service) detected"
    severity = 5
    categories = ["script", "malware"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        scheduler_rule = """
        rule PowershellScheduler {
            meta:
                author = "FDD @ Cuckoo Sandbox"
                description = "Rule for fake update service in powershell"
        
            strings:
                $task = "Microsoft Windows Driver Update" nocase
                // Windows path regex
                $cmd = /([a-zA-Z]\:|\\\\[\w\.]+\\[\w.$]+)\\([\w]+\\)*\w([\w.])+/ nocase
                $scheduler = "new-object -ComObject(\"Schedule.Service\")" nocase
                $opt = /\.Settings\.Hidden\s*=\s*\$true/ nocase
                $fn = "RegisterTaskDefinition" nocase
                $run = "SCHTASKS /run /TN" nocase
        
            condition:
                all of them
        }
       """
        for cmdline in self.get_command_lines():
            lower = cmdline.lower()

            if "powershell" not in lower:
                continue

            if "-enc" in lower or "-encodedcommand" in lower:
                # This has to be improved.
                script, args = None, shlex.split(cmdline)
                for idx, arg in enumerate(args):
                    if "-enc" not in arg.lower() and "-encodedcommand" not in arg.lower():
                        continue

                    try:
                        script = args[idx+1].decode("base64").decode("utf16")
                        rule = yara.compile(source=scheduler_rule)
                        matches = rule.match(data=script)

                        if matches:
                            self.mark_ioc("Malware family", "Powershell Scheduler")
                            for m in matches:
                                for string in m.strings:
                                    if string[1] == "$cmd":
                                        self.mark_ioc("Fake service path", string[2])
                            break
                    except Exception as e:
                        traceback.print_exc(e)
                        pass

        return self.has_marks()
