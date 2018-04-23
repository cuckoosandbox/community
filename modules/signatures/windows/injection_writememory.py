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

class InjectionWriteMemory(Signature):
    name = "injection_write_memory"
    description = "Potential code injection by writing to the memory of another process"
    severity = 3
    categories = ["injection"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_apinames = [
        "NtWriteVirtualmemory",
        "WriteProcessMemory",
    ]

    process_handles = ["0xffffffff", "0xffffffffffffffff"]

    def on_call(self, call, process):
        proc_handle = call["arguments"]["process_handle"]

        if len(call["arguments"]["buffer"]) > 0 and proc_handle not in self.process_handles:
            injected_pid = call["arguments"]["process_identifier"]
            call_process = self.get_process_by_pid(injected_pid)

            if not call_process or call_process["ppid"] != process["pid"]:
                self.mark_ioc(
                    "Process injection",
                    "Process %s injected into non-child %s" % (process["pid"],
                                                               injected_pid)
                )
            self.mark_call()

    def on_complete(self):
        return self.has_marks()

class InjectionWriteMemoryEXE(Signature):
    name = "injection_write_memory_exe"
    description = "Code injection by writing an executable or DLL to the memory of another process"
    severity = 3
    categories = ["injection", "unpacking"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_apinames = [
        "NtWriteVirtualmemory",
        "WriteProcessMemory",
    ]

    process_handles = ["0xffffffff", "0xffffffffffffffff"]

    def on_call(self, call, process):
        proc_handle = call["arguments"]["process_handle"]

        if call["arguments"]["buffer"].startswith("MZ") and proc_handle not in self.process_handles:
            injected_pid = call["arguments"]["process_identifier"]
            call_process = self.get_process_by_pid(injected_pid)

            if not call_process or call_process["ppid"] != process["pid"]:
                self.mark_ioc(
                    "Process injection",
                    "Process %s injected into non-child %s" % (process["pid"],
                                                               injected_pid)
                )
            self.mark_call()

    def on_complete(self):
        return self.has_marks()
