# Copyright (C) 2018 Kevin Ross
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

class VirtualPCDetectWindow(Signature):
    name = "antivm_virtualpc_window"
    description = "Detects VirtualPC through the presence of a window"
    severity = 3
    categories = ["anti-vm"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    ttp = ["T1057"]

    filter_categories = "ui",

    # Lowercase all indicators.
    indicators = [indicator.lower() for indicator in [
        "vmusrvc.exe",
        "vmsrvc.exe",
    ]]

    def on_call(self, call, process):
        for indicator in self.indicators:
            window_name = call["arguments"].get("window_name", "").lower()
            class_name = call["arguments"].get("class_name", "").lower()

            if indicator == window_name or indicator == class_name:
                self.mark_call()

    def on_complete(self):
        return self.has_marks()
