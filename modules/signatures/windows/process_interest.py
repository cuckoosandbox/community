# Copyright (C) 2015 Optiv Inc. (brad.spengler@optiv.com), Updated 2016 for Cuckoo 2.0
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

from lib.cuckoo.common.abstracts import Signature

class ProcessInterest(Signature):
    name = "process_interest"
    description = "Expresses interest in specific running processes"
    severity = 2
    categories = ["generic"]
    authors = ["Optiv", "Kevin Ross"]
    minimum = "2.0"
    evented = True
    ttp = ["T1057"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocessname = ""
        self.interested_processes = set()

    filter_apinames = "Process32NextW", "Process32FirstW"

    suspicious_procs = [
        # Process Injection Targets
        ("csrss.exe", "process: potential process injection target"),
        ("explorer.exe", "process: potential process injection target"),
        ("lsass.exe", "process: potential process injection target"),
        ("services.exe", "process: potential process injection target"),
        ("smss.exe", "process: potential process injection target"),
        ("svchost.exe", "process: potential process injection target"),
        ("userinit.exe", "process: potential process injection target"),
        ("wininit.exe", "process: potential process injection target"),
        ("winlogon.exe", "process: potential process injection target"),
        # Browser Inejction Targets
        ("chrome.exe", "process: potential browser injection target"),
        ("iexplore.exe", "process: potential browser injection target"),
        ("firefox.exe", "process: potential browser injection target"),
        ("microsoftedge.exe", "process: potential browser injection target"),
        ("opera.exe", "process: potential browser injection target"),
        ("safari.exe", "process: potential browser injection target"),
        # Sandbox Detection
        ("python.exe", "process: potential cuckoo sandbox detection"),
        ("pythonw.exe", "process: potential cuckoo sandbox detection"),
    ]

    def on_call(self, call, process):
        if call["api"] == "Process32NextW":
            if not call["status"]:
                self.lastprocessname = ""
            else:
                self.lastprocessname = call["arguments"]["process_name"].lower()
        else:
            # is Process32FirstW
            if self.lastprocessname:
                self.interested_processes.add(self.lastprocessname)

    def on_complete(self):
        if self.lastprocessname:
            self.interested_processes.add(self.lastprocessname)
        if len(self.interested_processes):
            for proc in self.interested_processes:
                description = "process"
                for suspicious in self.suspicious_procs:
                    if proc == suspicious[0]:
                        description = suspicious[1]
                        self.severity = 3
                self.mark_ioc(description, proc)

            return self.has_marks()

class InjectionProcessSearch(Signature):
    name = "injection_process_search"
    description = "Searches running processes potentially to identify processes for sandbox evasion, code injection or memory dumping"
    severity = 2
    categories = ["generic"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    ttp = ["T1057"]

    pids = []

    filter_apinames = "Process32FirstW", "Process32NextW",

    def on_call(self, call, process):
        if call["arguments"]["process_identifier"] not in self.pids:
            self.pids.append(call["arguments"]["process_identifier"])
            self.mark_call()

    def on_complete(self):
        if len(self.pids) > 10:
            return self.has_marks()
