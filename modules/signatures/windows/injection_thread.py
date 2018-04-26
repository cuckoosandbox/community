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

class InjectionCreateRemoteThread(Signature):
    name = "injection_createremotethread"
    description = "Creates a thread using CreateRemoteThread in a non-child process indicative of process injection"
    severity = 3
    categories = ["injection"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    references = ["www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process"]

    filter_apinames = [
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
    ]

    def on_call(self, call, process):
        if call["arguments"]["process_handle"] != "0xffffffff" and call["arguments"]["process_handle"] != "0xffffffffffffffff":
            injected_pid = call["arguments"]["process_identifier"]
            call_process = self.get_process_by_pid(injected_pid)
            if not call_process or call_process["ppid"] != process["pid"] and process["pid"] != injected_pid:
                self.mark_ioc(
                    "Process injection",
                    "Process %s created a remote thread in non-child process %s" % (process["pid"],
                                                               injected_pid)
                )
                self.mark_call()

    def on_complete(self):
        return self.has_marks()

class InjectionQueueApcThread(Signature):
    name = "injection_queueapcthread"
    description = "Creates a thread using NtQueueApcThread in a remote process potentially indicative of process injection"
    severity = 3
    categories = ["injection"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    references = ["www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process"]

    filter_apinames = [
        "NtQueueApcThread",
    ]

    def on_call(self, call, process):
        injected_pid = call["arguments"]["process_identifier"]
        if process["pid"] != injected_pid:
            self.mark_ioc(
                "Process injection",
                "Process %s created a thread in remote process %s" % (process["pid"],
                                                               injected_pid)
            )
            self.mark_call()

    def on_complete(self):
        return self.has_marks()

class ResumeThread(Signature):
    name = "injection_resumethread"
    description = "Resumed a suspended thread in a remote process potentially indicative of process injection"
    severity = 3
    categories = ["injection"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    references = ["www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process"]

    filter_apinames = [
        "NtResumeThread",
    ]

    def on_call(self, call, process):
        injected_pid = call["arguments"]["process_identifier"]
        if process["pid"] != injected_pid:
            self.mark_ioc(
                "Process injection",
                "Process %s resumed a thread in remote process %s" % (process["pid"],
                                                               injected_pid)
            )
            self.mark_call()

    def on_complete(self):
        return self.has_marks()

class NtSetContextThreadRemote(Signature):
    name = "injection_ntsetcontextthread"
    description = "Used NtSetContextThread to modify a thread in a remote process indicative of process injection"
    severity = 3
    categories = ["injection", "shellcode"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    references = ["www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process"]


    filter_apinames = [
        "NtSetContextThread",
    ]

    def on_call(self, call, process):
        injected_pid = call["arguments"]["process_identifier"]
        if process["pid"] != injected_pid:
            self.mark_ioc(
                "Process injection",
                "Process %s called NtSetContextThread to modify thread in remote process %s" % (process["pid"],
                                                               injected_pid)
            )
            self.mark_call()

    def on_complete(self):
        return self.has_marks()
