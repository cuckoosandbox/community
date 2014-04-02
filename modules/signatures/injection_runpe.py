# Copyright (C) 2014 glysbays
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

class InjectionRUNPE(Signature):
    name = "injection_runpe"
    description = "Process forking"
    severity = 2
    categories = ["injection"]
    authors = ["glysbaysb"]
    minimum = "1.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.sequence = 0
            self.process_handle = 0
            self.lastprocess = process

        if call["api"]  == "CreateProcessInternalW" and self.sequence == 0:
            self.sequence = 1
            self.process_handle = self.get_argument(call, "ProcessHandle")
            self.thread_handle = self.get_argument(call, "ThreadHandle")
        elif call["api"] == "NtUnmapViewOfSection" and self.sequence == 1:
            if self.get_argument(call, "ProcessHandle") == self.process_handle:
                self.sequence = 2
        elif (call["api"] == "NtWriteVirtualMemory" or call["api"] == "WriteProcessMemory" or call["api"] == "NtMapViewOfSection") and self.sequence == 2:
            if self.get_argument(call, "ProcessHandle") == self.process_handle:
                self.sequence = 3
        elif (call["api"].startswith("SetThreadContext")) and self.sequence == 3:
            if self.get_argument(call, "ThreadHandle") == self.thread_handle:
                self.sequence = 4
        elif call["api"] == "NtResumeThread" and self.sequence == 4:
            if self.get_argument(call, "ThreadHandle") == self.thread_handle:
                return True
