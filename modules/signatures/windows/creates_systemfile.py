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

class CreatesSystemFiles(Signature):
    name = "creates_system_files"
    description = "Creates a file in the Windows system directory"
    severity = 3
    categories = ["generic"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    indicators = [
        ".*\\\\Windows\\\\System\\\\.*",
        ".*\\\\Windows\\\\System32\\\\.*",
        ".*\\\\Windows\\\\SysWOW64\\\\.*",
    ]

    def on_complete(self):
        for indicator in self.indicators:
            for filepath in self.check_file(pattern=indicator, actions=["file_written"], regex=True, all=True):
                self.mark_ioc("file", filepath)
 
        return self.has_marks()
