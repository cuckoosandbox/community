# Copyright (C) 2016 Kevin Ross
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

try:
    import re2 as re
except ImportError:
    import re

class RamsomwareAppendsExtension(Signature):
    name = "ransomware_file_moves"
    description = "Appends a new file extension to more than %d files indicative of a ransomware file encryption process"
    severity = 3
    families = ["ransomware"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_apinames = "MoveFileWithProgressW", "MoveFileWithProgressTransactedW"

    def on_call(self, call, process):
        origfile = call["arguments"]["oldfilepath"]
        newfile = call["arguments"]["newfilepath"]
        if origfile != newfile:
            origextextract = re.search("^.*(\.[a-zA-Z0-9_\-]{1,}$)", origfile)
            if not origextextract:
                return None
            newextextract = re.search("^.*(\.[a-zA-Z0-9_\-]{1,}$)", newfile)
            if not newextextract:
                return None
            newextension = newextextract.group(1)
            if newextension != ".tmp":
                self.mark_call()

    def on_complete(self):
        if self.has_marks(500):
            self.description = self.description % 500
            self.severity = 6
        elif self.has_marks(100):
            self.description = self.description % 100
            self.severity = 5
        elif self.has_marks(50):
            self.description = self.description % 50
            self.severity = 4
        else:
            self.description = self.description % 5

        return self.has_marks(5)
