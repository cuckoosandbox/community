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

class ExecutesHTA(Signature):
    name = "executes_hta"
    description = "Executes or displays a HTA file"
    severity = 2
    categories = ["ransomware", "downloader", "exploit"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    def on_complete(self):
        for cmdline in self.get_command_lines():
            lower = cmdline.lower()

            if "mshta" in lower:
                self.mark(cmdline=cmdline)

        return self.has_marks()

class ExecutesHTAJavaScript(Signature):
    name = "executes_hta_javascript"
    description = "Executes JavaScript using the mshta utility"
    severity = 3
    categories = ["ransomware", "downloader", "exploit"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    def on_complete(self):
        for cmdline in self.get_command_lines():
            lower = cmdline.lower()

            if "mshta" in lower and "javascript:" in lower:
                self.mark(cmdline=cmdline)

        return self.has_marks()
