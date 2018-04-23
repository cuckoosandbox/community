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

class InjectionExplorer(Signature):
    name = "injection_explorer"
    description = "Performs code injection into the Explorer process using the Shell_TrayWnd technique"
    severity = 3
    categories = ["injection"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    references = ["www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process"]

    filter_apinames = [
        "Process32NextW",
        "FindWindowW",
        "SendNotifyMessageA",
    ]

    explorerpids = []
    windowhandle = ""
    injected = False

    def on_call(self, call, process):
        if call["api"] == "Process32NextW":
            if call["arguments"]["process_name"] == "explorer.exe":
                self.explorerpids.append(call["arguments"]["process_identifier"])
                self.mark_call()

        elif call["api"] == "FindWindowW":
            if call["arguments"]["class_name"] == "Shell_TrayWnd":
                self.windowhandle = call["return_value"]
                self.mark_call()

        elif call["api"] == "SendNotifyMessageA":
            if call["arguments"]["process_identifier"] in self.explorerpids and int(call["arguments"]["window_handle"], 16) == self.windowhandle:
                self.injected = True
                self.mark_call()

    def on_complete(self):
        if self.injected:
            return self.has_marks()
