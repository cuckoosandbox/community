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

class ConsoleOutput(Signature):
    name = "console_output"
    description = "Command line console output was observed"
    severity = 1
    categories = ["command"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_apinames = [
        "WriteConsoleA",
        "WriteConsoleW",
    ]

    def on_call(self, call, process):
        buf = call["arguments"]["buffer"]
        if len(buf) > 0 and any(c.isalpha() for c in buf):
            self.mark_call()

    def on_complete(self):
        return self.has_marks()
