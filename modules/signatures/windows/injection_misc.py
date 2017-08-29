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

class InjectionDuplicateHandle(Signature):
    name = "injection_duplicate_handle"
    description = "Duplicates the process handle of an other process to obtain access rights to that process"
    severity = 3
    categories = ["injection", "privilege escalation"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_apinames = [
        "NtDuplicateObject",
    ]

    def on_call(self, call, process):
        if call["arguments"]["source_process_identifier"] != call["arguments"]["target_process_identifier"] and call["arguments"]["source_process_identifier"] != 0 and not call["arguments"]["source_process_handle"].startswith("0xfffffff") and call["arguments"]["target_process_handle"].startswith("0xfffffff"):
            self.mark_call()

    def on_complete(self):
        return self.has_marks()
