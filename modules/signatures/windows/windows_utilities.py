# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class UsesWindowsUtilities(Signature):
    name = "uses_windows_utilities"
    description = "Uses Windows utilities for basic Windows functionality"
    severity = 2
    categories = ["commands", "lateral"]
    authors = ["Cuckoo Technologies", "Kevin Ross"]
    minimum = "2.0"
    references = ["http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html"]

    utilities = [
        "at ",
        "at.exe",
        "attrib",
        "copy",
        "dir ",
        "dir.exe",
        "echo"
        "erase",
        "fsutil",
        "getmac",
        "ipconfig",
        "md ",
        "md.exe",
        "mkdir",
        "move ",
        "move.exe",
        "nbtstat",
        "net ",
        "net.exe",
        "netsh",
        "netstat",
        "nslookup",
        "ping",
        "powershell",
        "qprocess",
        "query ",
        "query.exe",
        "quser",
        "qwinsta",
        "reg ",
        "reg.exe",
        "regsrv32",
        "ren ",
        "ren.exe",
        "rename",
        "route",
        "runas",
        "rwinsta",
        "sc ",
        "sc.exe",
        "schtasks",
        "set ",
        "set.exe",
        "shutdown",
        "systeminfo",
        "tasklist",
        "telnet",
        "tracert",
        "tree ",
        "tree.exe",
        "type",
        "ver ",
        "ver.exe",
        "whoami",
        "wmic",
        "wusa"
    ]

    def on_complete(self):
        for cmdline in self.get_command_lines():
            for utility in self.utilities:
                if cmdline.lower().startswith(utility):
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()

class SuspiciousCommandTools(Signature):
    name = "suspicious_command_tools"
    description = "Uses suspicious command line tools or Windows utilities"
    severity = 3
    categories = ["commands", "lateral"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    utilities = [
        "accesschk",
        "accessenum",
        "adexplorer",
        "adinsight",
        "adrestore",
        "autologon",
        "autoruns",
        "bitsadmin",
        "bginfo",
        "cacls",
        "csvde",
        "del ",
        "del.exe",
        "dsquery",
        "icacls",
        "klist",
        "psexec",        
        "psfile",
        "psgetsid",
        "psinfo",
        "psping",
        "pskill",
        "pslist",
        "psloggedon",
        "psloglist",
        "pspasswd",
        "psservice",
        "psshutdown",
        "pssuspend",
        "rd ",
        "rd.exe",
        "rexec",
        "shareenum",
        "shellrunas",
        "taskkill",
        "volumeid",
        "wevtutil",
        "whois"
        "xcacls"
    ]

    def on_complete(self):
        for cmdline in self.get_command_lines():
            for utility in self.utilities:
                if cmdline.lower().startswith(utility):
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()

class LongCommandLine(Signature):
    name = "long_command_line"
    description = "A suspiciously long command line or script command was executed"
    severity = 2
    categories = ["commands"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    utilities = [
        "cmd",
        "cscript",
        "hta",
        "powershell",
        "wscript",
    ]

    def on_complete(self):
        for cmdline in self.get_command_lines():
            for utility in self.utilities:
                if cmdline.lower().startswith(utility) and len(cmdline) > 250:
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()

class AddsUser(Signature):
    name = "adds_user"
    description = "Uses windows command to add a user to the system"
    severity = 2
    categories = ["commands"]
    authors = ["Kevin"]
    minimum = "2.0"

    def on_complete(self):
        for cmdline in self.get_command_lines():
                if cmdline.lower().startswith("net") and "user /add" in cmdline.lower():
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()

class AddsUserAdmin(Signature):
    name = "adds_user_admin"
    description = "Uses windows command to add a user to the administrator group"
    severity = 3
    categories = ["commands"]
    authors = ["Kevin"]
    minimum = "2.0"

    def on_complete(self):
        for cmdline in self.get_command_lines():
                if cmdline.lower().startswith("net") and "localgroup administrators" in cmdline.lower():
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()
