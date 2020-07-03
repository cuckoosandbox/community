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

class InjectionModifiesMemory(Signature):
    name = "injection_modifies_memory"
    description = "Manipulates memory of a non-child process indicative of process injection"
    severity = 3
    categories = ["injection"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    references = ["www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process"]

    filter_apinames = [
        "NtAllocateVirtualMemory",
        "NtMapViewOfSection",
        "NtProtectVirtualMemory",
        "NtUnmapViewOfSection",
        "VirtualProtectEx",
    ]

    def on_call(self, call, process):
        if call["arguments"]["process_handle"] != "0xffffffff" and call["arguments"]["process_handle"] != "0xffffffffffffffff":
            injected_pid = call["arguments"]["process_identifier"]
            call_process = self.get_process_by_pid(injected_pid)
            if not call_process or call_process["ppid"] != process["pid"]:
                self.mark_ioc(
                    "Process injection",
                    "Process %s manipulating memory of non-child process %s" % (process["pid"],
                                                               injected_pid)
                )
                self.mark_call()

    def on_complete(self):
        return self.has_marks()
