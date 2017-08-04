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

class InjectionWriteMemoryEXE(Signature):
    name = "injection_write_memory_exe"
    description = "Writes an executable/dll to the memory of another process"
    severity = 3
    categories = ["injection", "unpacking"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_apinames = [
        "NtWriteVirtualmemory",
        "WriteProcessMemory",
    ]

    def on_call(self, call, process):
        if call["arguments"]["buffer"].startswith("MZ") and not call["arguments"]["process_handle"].startswith("0xfffffff"):
            self.mark_call()

    def on_complete(self):
        return self.has_marks()
