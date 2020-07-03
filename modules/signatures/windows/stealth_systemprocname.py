# Copyright (C) 2017 Kevin Ross
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

class StealthSystemProcName(Signature):
    name = "stealth_system_procname"
    description = "Created a process named as a common system process"
    severity = 2
    categories = ["stealth"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    ttp = ["T1036"]

    filter_apinames = "CreateProcessInternalW", "ShellExecuteExW",

    systemprocs = [
        "csrss.exe",
        "explorer.exe",
        "lsass.exe",
        "spoolsv.exe",
        "services.exe",
        "svchost.exe",
        "taskmgr.exe",
        "winlogin.exe",
    ]

    def on_call(self, call, process):
        filepath = call["arguments"]["filepath"].lower()
        for systemproc in self.systemprocs:
            if filepath.endswith(systemproc):
                if not filepath.endswith("svchost.exe"):
                    self.severity = 3
                self.mark_call()

    def on_complete(self):
        return self.has_marks()
