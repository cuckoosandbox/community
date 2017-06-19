# Copyright (C) 2010-2015 Cuckoo Foundation. 2016 Brad Spengler
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DisablesTracing(Signature):
    name = "disables_tracing"
    description = "Disables WScript tracing features"
    severity = 3
    categories = ["tracing"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"
    filter_apinames = set(["RegSetValueExA", "RegSetValueExW", "NtSetValueKey"])

    regkeys = [
        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\wscript_RASAPI32\EnableFileTracing",
        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\wscript_RASAPI32\EnableConsoleTracing",
        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\wscript_RASMANCS\EnableFileTracing",
        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\wscript_RASMANCS\EnableConsoleTracing",
    ]
    
    masks_regkeys = [
        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\wscript_RASAPI32\FileTracingMask",
        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\wscript_RASAPI32\ConsoleTracingMask",
        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\wscript_RASMANCS\FileTracingMask",
        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\wscript_RASMANCS\ConsoleTracingMask",
    ]

    def on_call(self, call, process):
        args = call["arguments"]

        if not "regkey" in args or not "value" in args:
            return

        if args["regkey"] in self.regkeys and args["value"] == 0:
            self.mark_call()

        if args["regkey"] in self.masks_regkeys and args["value"] == -65536:
            self.mark_call()

    def on_complete(self):
        return self.has_marks()
