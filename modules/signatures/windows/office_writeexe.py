# Copyright (C) 2015 Will Metcalf william.metcalf@gmail.com, Updated 2016 for Cuckoo 2.0
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

class OfficeWriteEXE(Signature):
    name = "office_write_exe"
    description = "An office file wrote an executable file to disk"
    severity = 3
    categories = ["exploit", "downloader", "virus"]
    authors = ["Will Metcalf"]
    minimum = "2.0"

    office_proc_list =["wordview.exe","winword.exe","excel.exe","powerpnt.exe","outlook.exe"]

    filter_apinames = set(["NtWriteFile"])
    filter_analysistypes = set(["file"])

    def on_call(self, call, process):
        pname = process["process_name"].lower()
        if pname in self.office_proc_list:
            buff = call["arguments"]["buffer"]
            if buff and len(buff) > 2 and "MZ" in buff and "This program" in buff:
                self.mark_call()

    def on_complete(self):
        return self.has_marks()
