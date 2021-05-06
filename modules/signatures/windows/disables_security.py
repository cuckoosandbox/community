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
    ttp = ["T1089", "T1112"]

    regkeys_re = [
        ("HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System\\\\EnableLUA", "attempts to disable user access control"),
        ("HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Security\\ Center\\\\AntiVirusOverride", "attempts to disable antivirus notifications"),
        ("HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Security\\ Center\\\\AntiVirusDisableNotify", "attempts to disable antivirus notifications"),
        ("HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Security\\ Center\\\\FirewallDisableNotify", "attempts to disable firewall notifications"),
        ("HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Security\\ Center\\\\FirewallOverride", "attempts to disable firewall notifications"),
        ("HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Security\\ Center\\\\UpdatesDisableNotify", "attempts to disable windows update notifications"),
        ("HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Security\\ Center\\\\UacDisableNotify", "disables user access control notifications"),
        ("HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\ControlSet001\\\\services\\\\SharedAccess\\\\Parameters\\\\FirewallPolicy\\\\StandardProfile\\\\EnableFirewall", "attempts to disable windows firewall"),
        ("HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\ControlSet001\\\\services\\\\SharedAccess\\\\Parameters\\\\FirewallPolicy\\\\StandardProfile\\\\DoNotAllowExceptions", "attempts to disable firewall exceptions"),
        ("HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\ControlSet001\\\\services\\\\SharedAccess\\\\Parameters\\\\FirewallPolicy\\\\StandardProfile\\\\DisableNotifications", "attempts to disable firewall notifications"),
        (".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Windows\\ Defender\\\\.*", "attempts to disable windows defender"),
        (".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Policies\\\\Microsoft\\\\Windows\\ Defender\\\\.*", "attempts to modify windows defender policies"),
        (".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\services\\\\WinDefend\\\\.*", "attempts to disable windows defender"),        
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            for regkey in self.check_key(pattern=indicator[0], regex=True, actions=["regkey_written"], all=True):
                self.mark(
                    description=indicator[1],
                    registry=regkey,                     
                )
                self.severity += 1

        self.severity = min(self.severity, 5)
        return self.has_marks()

class UACBypassRegistryHijack(Signature):
    name = "uac_bypass_registry_hijack"
    description = "User Access Control (UAC) bypass using eventvwr registry hijack method"
    severity = 3
    categories = ["anti-av"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    references = ["enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/"]

    def on_complete(self):
        for process in self.get_results("behavior", {}).get("generic", []):
            if "eventvwr.exe" in process["process_name"].lower():
                continue

        for cmdline in self.get_command_lines():
            if "\mscfile\shell\open\command" in cmdline.lower():
                self.mark_ioc("cmdline", cmdline)
        
        return self.has_marks()
