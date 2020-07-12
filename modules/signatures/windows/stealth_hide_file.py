# Copyright (C) 2017 Cuckoo Sandbox
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

class StealthHideFile(Signature):
    name = "stealth_hide_file"
    description = "Hides one or more files"
    severity = 2
    categories = ["stealth"]
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"
    evented = True

    filter_apinames = set(["SetFileAttributesW", "SetFileAttributesA"])

    def on_call(self, call, process):
        if not "filepath" in call["arguments"] or not "file_attributes" in call["arguments"]:
            return

        filepath = call["arguments"]["filepath"]
        attr     = call["arguments"]["file_attributes"]
        # check for attr == 2 (FILE_ATTRIBUTE_HIDDEN)
        if attr != 2:
            return

        self.mark_call()

    def on_complete(self):
        return self.has_marks()
