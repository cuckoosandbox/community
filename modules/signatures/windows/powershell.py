# Copyright (C) 2015-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from lib.cuckoo.common.abstracts import Signature

class SuspiciousPowershell(Signature):
    name = "suspicious_powershell"
    description = "Creates a suspicious Powershell process"
    severity = 3
    categories = ["script", "dropper", "downloader", "packer"]
    authors = ["Kevin Ross", "Cuckoo Technologies", "FDD"]
    minimum = "2.0"

    def on_complete(self):
        for cmdline in self.get_command_lines():
            lower = cmdline.lower()
            features = ""

            if "powershell" not in lower:
                continue

            epre = re.compile("\-[e^]{1,2}[xecution]*[p^]{0,2}[olicy]*[\s]+bypass")
            m = epre.search(lower)
            if m:
                if features == "":
                    features = "Attempts to bypass execution policy"
                else:
                    features += ", Attempts to bypass execution policy"

            epre = re.compile("\-[e^]{1,2}[xecution]*[p^]{0,2}[olicy]*[\s]+unrestricted")
            m = epre.search(lower)
            if m:
                if features == "":
                    features = "Attempts to bypass execution policy"
                else:
                    features += ", Attempts to bypass execution policy"

            nopre = re.compile("\-nop[rofile]*")
            m = nopre.search(lower)
            if m:
                if features == "":
                    features = "Does not load current user profile"
                else:
                    features += ", Does not load current user profile"

            nolre = re.compile("\-nol[og]*")
            m = nolre.search(lower)
            if m:
                if features == "":
                    features = "Hides the copyright banner when PowerShell launches"
                else:
                    features += ", Hides the copyright banner when PowerShell launches"

            hiddenre = re.compile("\-[w^]{1,2}[indowstyle^]*[\s]+hidden")
            m = hiddenre.search(lower)
            if m:
                if features == "":
                    features = "Attempts to execute command with a hidden window"
                else:
                    features += ", Attempts to execute command with a hidden window"

            nonire = re.compile("\-noni[nteraciv]*")
            m = nonire.search(lower)
            if m:
                if features == "":
                    features = "Prevents creating an interactive prompt for the user"
                else:
                    features += ", Prevents creating an interactive prompt for the user"

            if "downloadfile(" in lower or "downloadstring(" in lower:
                if features == "":
                    features = "Uses powershell to execute a file download from the command line"
                else:
                    features += ", Uses powershell to execute a file download from the command line"

            if "start-process" in lower or "shellexecute" in lower or "createprocess" in lower:
                if features == "":
                    features = "Creates a new process"
                else:
                    features += ", Creates a new process"
                    
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

            if "-enc" in lower:
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

class AmsiBypass(Signature):
    name = "amsi_bypass"
    description = "Powershell script bypasses AMSI (Antimalware Scan Interface) by reporting a failure in AMSI initialization"
    severity = 5
    categories = ["script", "malware", "powershell", "amsi"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"
    ttp = ["T1086", "T1089"]

    def on_yara(self, category, filepath, match):
        if match.name != "PowershellAMSI":
            return

        self.mark_ioc("function", match.string("fn1", 0))
        self.mark_ioc("function", match.string("fn2", 0))
        self.mark_ioc("function", match.string("fn3", 0))
        return True

class PowershellBitsTransfer(Signature):
    name = "powershell_bitstransfer"
    description = "Powershell BITS Transfer detected (dropper malware)"
    severity = 5
    categories = ["script", "dropper", "downloader", "malware", "powershell"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"
    ttp = ["T1197"]

    def on_yara(self, category, filepath, match):
        if match.name != "PowershellBitsTransfer":
            return

        self.mark_config({
            "family": "Powershell BITS Transfer Dropper",
            "url": match.string("Payload", 0),
        })
        return True

class PowershellDdiRc4(Signature):
    name = "powershell_ddi_rc4"
    description = "Powershell downloads RC4 crypted data and executes it"
    severity = 5
    categories = ["script", "dropper", "downloader", "malware", "powershell"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"
    ttp = ["T1112", "T1086"]

    def on_yara(self, category, filepath, match):
        if match.name != "PowershellDdiRc4":
            return

        host = match.string("Host", 0)
        path = match.string("Path", 0).strip("'")
        key = match.string("Key", 0)

        if "'" in key:
            key = key.split("'")[1]
        if '"' in key:
            key = key.split('"')[1]

        self.mark_config({
            "family": "Powershell DDI RC4 (downloader)",
            "url": "%s%s" % (host, path),
            "key": key,
        })
        return True

class PowershellDFSP(Signature):
    name = "powershell_dfsp"
    description = "Powershell Downloader DFSP detected"
    severity = 5
    categories = ["script", "dropper", "downloader", "malware"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"
    ttp = ["T1112", "T1086"]

    def on_yara(self, category, filepath, match):
        if match.name != "PowershellDFSP":
            return

        self.mark_config({
            "family": "Powershell Downloader DFSP",
            "url": match.string("Payload", 0),
        })
        return True

class PowershellDI(Signature):
    name = "powershell_di"
    description = "Powershell script has download & invoke calls"
    severity = 1
    categories = ["script", "dropper", "downloader", "malware", "powershell"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"
    ttp = ["T1086"]

    def on_yara(self, category, filepath, match):
        if match.name != "PowershellDI":
            return

        for name in ("d1", "d2", "d3", "d4"):
            if name in match.offsets:
                url = match.string(name, 0)
                break

        if url.count('"') == 2:
            url = url.split('"')[1]
        elif url.count("'") == 2:
            url = url.split("'")[1]
        else:
            url = None

        if url:
            self.mark_config({
                "family": "Powershell Download & Invoke",
                "url": url,
            })
            return True

class PowershellDownload(Signature):
    name = "powershell_download"
    description = "URL downloaded by powershell script"
    severity = 2
    categories = ["downloader"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"
    ttp = ["T1112", "T1086"]

    filter_apinames = [
        "recv",
    ]

    def on_call(self, call, process):
        if process["process_name"].lower() != "powershell.exe":
            return

        if call["arguments"]["buffer"]:
            self.mark_ioc("Data received", call["arguments"]["buffer"])

    def on_complete(self):
        return self.has_marks()

class PowershellEmpire(Signature):
    name = "powershell_empire"
    description = "Powershell Empire detected"
    severity = 5
    categories = ["script", "dropper", "downloader", "malware"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"
    ttp = ["T1086"]

    def on_yara(self, category, filepath, match):
        if match.name != "PowershellEmpire":
            return

        self.mark_config({
            "family": "Powershell Empire",
        })
        return True

class PowershellMeterpreter(Signature):
    name = "powershell_meterpreter"
    description = "Meterpreter execution throught Powershell detected"
    severity = 5
    categories = ["script", "meterpreter", "powershell", "malware"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"
    ttp = ["T1086"]

    def on_yara(self, category, filepath, match):
        if match.name != "PowershellMeterpreter":
            return

        host = match.string("Host", 0).split()[1]
        port = match.string("Port", 0).split()[1]
        package = match.string("Package", 0)

        self.mark_config({
            "family": "Powershell Meterpreter",
            "url": "tcp://%s:%s" % (host, port),
            "type": package,
        })
        return True

class PowershellRequest(Signature):
    name = "powershell_request"
    description = "Powershell is sending data to a remote host"
    severity = 2
    categories = ["downloader"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"
    ttp = ["T1086", "T1071"]

    filter_apinames = [
        "send",
    ]

    def on_call(self, call, process):
        if process["process_name"].lower() == "powershell.exe":
            self.mark_ioc("Data sent", call["arguments"]["buffer"])

    def on_complete(self):
        return self.has_marks()

class PowershellCcDns(Signature):
    name = "powershell_c2dns"
    description = "Powershell C&C bot through DNS detected"
    severity = 5
    categories = ["script", "bot", "dns", "malware"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"
    ttp = ["T1086", "T1071"]

    def on_yara(self, category, filepath, match):
        if match.name != "PowershellCcDns":
            return

        dns = match.string("DNS", 0).replace("nslookup -q=txt", "").strip()
        self.mark_config({
            "family": "Powershell DNS TXT Dropper",
            "url": dns,
        })
        return True

class PowershellUnicorn(Signature):
    name = "powershell_unicorn"
    description = "A Powershell script generated using the unicorn technique (shellcode injection in powershell process) has been detected"
    severity = 5
    categories = ["script", "dropper", "downloader", "malware"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"
    ttp = ["T1086"]

    def on_yara(self, category, filepath, match):
        if match.name != "UnicornGen":
            return

        self.mark_config({
            "family": "Unicorn by trustedsec.com",
        })
        return True
