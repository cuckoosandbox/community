# Copyright (C) 2010-2015 Cuckoo Foundation. 2016 Brad Spengler
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DisablesSecurity(Signature):
    name = "disables_security"
    description = "Disables Windows Security features"
    severity = 3
    categories = ["anti-av"]
    authors = ["Cuckoo Technologies", "Brad Spengler"]
    minimum = "2.0"

    regkeys_re = [
        ("HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System\\\\EnableLUA", "registry: attempts to disable user access control"),
        ("HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Security\\ Center\\\\AntiVirusOverride", "registry: attempts to disable antivirus notifications"),
        ("HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Security\\ Center\\\\AntiVirusDisableNotify", "registry: attempts to disable antivirus notifications"),
        ("HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Security\\ Center\\\\FirewallDisableNotify", "registry: attempts to disable firewall notifications"),
        ("HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Security\\ Center\\\\FirewallOverride", "registry: attempts to disable firewall notifications"),
        ("HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Security\\ Center\\\\UpdatesDisableNotify", "registry: attempts to disable windows update notifications"),
        ("HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Security\\ Center\\\\UacDisableNotify", "registry: disables user access control notifications"),
        ("HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\ControlSet001\\\\services\\\\SharedAccess\\\\Parameters\\\\FirewallPolicy\\\\StandardProfile\\\\EnableFirewall", "registry: attempts to disable windows firewall"),
        ("HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\ControlSet001\\\\services\\\\SharedAccess\\\\Parameters\\\\FirewallPolicy\\\\StandardProfile\\\\DoNotAllowExceptions", "registry: attempts to disable firewall exceptions"),
        ("HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\ControlSet001\\\\services\\\\SharedAccess\\\\Parameters\\\\FirewallPolicy\\\\StandardProfile\\\\DisableNotifications", "registry: attempts to disable firewall notifications"),
        (".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Windows\\ Defender\\\\.*", "registry: attempts to disable windows defender"),
        (".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Policies\\\\Microsoft\\\\Windows\\ Defender\\\\.*", "registry: attempts to modify windows defender policies"),
        (".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\services\\\\WinDefend\\\\.*", "registry: attempts to disable windows defender"),        
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            for regkey in self.check_key(pattern=indicator[0], regex=True, actions=["regkey_written"], all=True):
                self.mark_ioc(indicator[1], indicator[0])
                self.severity += 1

        self.severity = min(self.severity, 5)
        return self.has_marks()
