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
    categories = ["injection", "privilege_escalation"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_apinames = [
        "NtDuplicateObject",
    ]

    def on_call(self, call, process):
        sourcepid = call["arguments"]["source_process_identifier"]
        targetpid = call["arguments"]["target_process_identifier"]
        sourcehandle = call["arguments"]["source_process_handle"]
        targethandle = call["arguments"]["target_process_handle"]
        if sourcepid != targetpid and sourcepid != 0 and sourcehandle != "0xffffffff" and sourcehandle != "0xffffffffffffffff" and (targethandle == "0xffffffff" or targethandle == "0xffffffffffffffff"):
            self.mark_call()

    def on_complete(self):
        return self.has_marks()

class OpenProcessNonChild(Signature):
    name = "openprocess_nonchild"
    description = "Attempts to open access to a non-child process"
    severity = 2
    categories = ["injection", "infostealer"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    references = ["www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process"]

    filter_apinames = [
        "NtOpenProcess",
    ]

    def on_call(self, call, process):
        if call["arguments"]["process_handle"] != "0xffffffff" and call["arguments"]["process_handle"] != "0xffffffffffffffff":
            injected_pid = call["arguments"]["process_identifier"]
            call_process = self.get_process_by_pid(injected_pid)
            if not call_process or call_process["ppid"] != process["pid"] and process["pid"] != injected_pid:
                self.mark_ioc(
                    "Opened Process",
                    "Process %s accessed non-child process %s" % (process["pid"],
                                                               injected_pid)
                )
                self.mark_call()

    def on_complete(self):
        return self.has_marks()

class CreateProcessSuspended(Signature):
    name = "create_process_suspended"
    description = "Created a process in a suspended state indicative of process hollowing code injection or unpacking"
    severity = 3
    categories = ["injection", "packer"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    references = ["www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process"]

    filter_apinames = [
        "CreateProcessInternalW",
    ]

    def on_call(self, call, process):
        if "CREATE_SUSPENDED" in call["flags"]["creation_flags"]:
            self.mark_call()

    def on_complete(self):
        return self.has_marks()
