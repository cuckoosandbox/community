# Copyright (C) 2010-2016 Cuckoo Foundation, Kevin Ross
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import shlex

from lib.cuckoo.common.abstracts import Signature

class PowershellCommand(Signature):
    name = "powershell_command"
    description = "Creates a Powershell process"
    severity = 2
    categories = ["script"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    def on_complete(self):
        for cmdline in self.get_command_lines():
            lower = cmdline.lower()
            if "powershell" in lower:            
                self.mark_ioc("cmdline", cmdline)

        return self.has_marks()

class SuspiciousPowershell(Signature):
    name = "suspicious_powershell"
    description = "Creates a suspicious Powershell process"
    severity = 3
    categories = ["script", "dropper", "downloader", "packer"]
    authors = ["Kevin Ross", "Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        for cmdline in self.get_command_lines():
            lower = cmdline.lower()
            features = ""

            if "powershell" not in lower:
                continue

            if "-ep bypass" in lower or "-executionpolicy bypass" in lower:
                if features == "":
                    features = "Attempts to bypass execution policy"
                else:
                    features += ", Attempts to bypass execution policy"

            if "-ep unrestricted" in lower or "-executionpolicy unrestricted" in lower:
                if features == "":
                    features = "Attempts to run an unrestricted execution policy"
                else:
                    features += ", Attempts to run an unrestricted execution policy"         

            if "-nop" in lower or "-noprofile" in lower:
                if features == "":
                    features = "Does not load current user profile"
                else:
                    features += ", Does not load current user profile"

            if "-w hidden" in lower or "-windowstyle hidden" in lower:
                if features == "":
                    features = "Attempts to execute command with a hidden window"
                else:
                    features += ", Attempts to execute command with a hidden window"

            if "downloadfile(" in lower:
                if features == "":
                    features = "Downloads a file"
                else:
                    features += ", Downloads a file"

            if "start-process" in lower or "shellexecute" in lower or "createprocess" in lower:
                if features == "":
                    features = "Creates a new process"
                else:
                    features += ", Creates a new process"

            if "-noni" in lower:
                if features == "":
                    features = "Creates a non-interactive prompt"
                else:
                    features += ", Creates a non-interactive prompt"
                    
            if "system.net.webrequest" in lower and "create(" in lower and "getresponse" in lower:
                if features == "":
                    features = "Uses System.Net.WebRequest method to perform a HTTP request"
                else:
                    features += ", Uses System.Net.WebRequest method to perform a HTTP request"
                    
            if "start-bitstransfer" in lower:
                if features == "":
                    features = "Uses BitsTransfer to download a file"
                else:
                    features += ", Uses BitsTransfer to download a file"
                    
            if "invoke-item" in lower:
                if features == "":
                    features = "Uses Invoke-Item to execute a file"
                else:
                    features += ", Uses Invoke-Item to execute a file"

            if "-enc" in lower or "-encodedcommand" in lower:
                # This has to be improved.
                script, args = None, shlex.split(cmdline)
                for idx, arg in enumerate(args):
                    if "-enc" not in arg.lower() and "-encodedcommand" not in arg.lower():
                        continue

                    try:
                        script = args[idx+1].decode("base64").decode("utf16")
                        break
                    except:
                        pass

                if features == "":
                    features = "Uses a base64 encoded command value"
                else:
                    features += ", Uses a base64 encoded command value"

            if len(features) > 0:
                if "base64 encoded command value" in features:
                    self.mark(cmdline=cmdline, description=features, script=script)
                else:                 
                    self.mark(cmdline=cmdline, description=features)

        return self.has_marks()
