# Copyright (C) 2016 Kevin Ross, Code slightly modified From Will Metcalf's original signature signature https://github.com/spender-sandbox/community-modified/blob/master/modules/signatures/office_write_exe.py
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

class WscriptWriteEXE(Signature):
    name = "wscript_write_exe"
    description = "Wscript.exe process wrote an executable file to disk"
    severity = 3
    categories = ["downloader", "virus"]
    authors = ["Will Metcalf"]
    minimum = "2.0"

    script_proc_list =["wscript.exe"]

    filter_apinames = set(["NtWriteFile"])
    filter_analysistypes = set(["file"])

    def on_call(self, call, process):
        pname = process["process_name"].lower()
        if pname in self.script_proc_list:
            buff = call["arguments"]["buffer"]
            if buff and len(buff) > 2 and buff.startswith("MZ") and "This program" in buff:
                self.mark_call()

    def on_complete(self):
        return self.has_marks()
