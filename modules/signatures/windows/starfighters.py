# Copyright (C) 2015 KillerInstinct, Updated 2016 for cuckoo 2.0
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import string

from lib.cuckoo.common.abstracts import Signature

class StarfightersBehavior(Signature):
    name = "starfighters_behavior"
    description = "Exhibits behavior characteristic of Starfighters malware"
    severity = 3
    categories = ["rat", "malware"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"
    calls = {}

    filter_apinames = set(["CoCreateInstance", "RegSetValueExA", 
        "RegSetValueExW", "NtSetValueKey"])

    regkeys = [
        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\wscript_RASAPI32\EnableFileTracing",
        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\wscript_RASAPI32\EnableConsoleTracing",
        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\wscript_RASMANCS\EnableFileTracing",
        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\wscript_RASMANCS\EnableConsoleTracing",
        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\wscript_RASAPI32\FileTracingMask",
        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\wscript_RASAPI32\ConsoleTracingMask",
        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\wscript_RASMANCS\FileTracingMask",
        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\wscript_RASMANCS\ConsoleTracingMask",
    ]

    def on_call(self, call, process):
        args = call["arguments"]
        if call["api"] == "CoCreateInstance":
            # CLSID for VB_Script_Language
            if args["clsid"] == "{b54f3741-5b07-11cf-a4b0-00aa004a55e8}":
                pid = process["pid"]
                if pid not in self.calls:
                    self.calls[pid] = []
                self.calls[pid].append(call)

        elif (call["api"] == "RegSetValueExA" or call["api"] == "RegSetValueExW"
                or call["api"] == "NtSetValueKey"):
            if args["regkey"] in self.regkeys:
                pid = process["pid"]
                if pid not in self.calls:
                    self.calls[pid] = []
                self.calls[pid].append(call)

    def on_complete(self):
        for pid, calls in self.calls.iteritems():
            if len(calls) >= 5:
                return True
