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

class RamsomwareFileMoves(Signature):
    name = "ransomware_file_moves"
    description = "Performs more than %d file moves indicative of a ransomware file encryption process"
    severity = 3
    families = ["ransomware"]
    minimum = "2.0"

    filter_apinames = "MoveFileWithProgressW", "MoveFileWithProgressTransactedW"

    def on_call(self, call, process):
        origfile = call["arguments"]["oldfilepath"]
        newfile = call["arguments"]["newfilepath"]
        if not origfile.endswith(".tmp") and not newfile.endswith(".tmp"):
            self.mark_call()

    def on_complete(self):
        if self.has_marks(1000):
            self.description = self.description % 500
            self.severity = 6
        if self.has_marks(600):
            self.description = self.description % 500
            self.severity = 5
        elif self.has_marks(100):
            self.description = self.description % 100
            self.severity = 4
        elif self.has_marks(50):
            self.description = self.description % 50
            self.severity = 3

        return self.has_marks(50)

class RansomwareAppendsExtension(Signature):
    name = "ransomware_appends_extensions"
    description = "Appends a new file extension to more than %d files indicative of a ransomware file encryption process"
    severity = 3
    families = ["ransomware"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_apinames = "MoveFileWithProgressW", "MoveFileWithProgressTransactedW"

    def on_call(self, call, process):
        origfile = call["arguments"]["oldfilepath"]
        newfile = call["arguments"]["newfilepath"]
        if origfile != newfile and not origfile.endswith(".tmp") and not newfile.endswith(".tmp"):
            self.mark_call()

    def on_complete(self):
        if self.has_marks(1000):
            self.description = self.description % 500
            self.severity = 6
        if self.has_marks(600):
            self.description = self.description % 500
            self.severity = 5
        elif self.has_marks(100):
            self.description = self.description % 100
            self.severity = 4
        elif self.has_marks(50):
            self.description = self.description % 50
            self.severity = 3

        return self.has_marks(50)

from lib.cuckoo.common.abstracts import Signature

class RansomwareDroppedFiles(Signature):
    name = "ransomware_dropped_files"
    description = "Drops many unknown file mime types indicative of ransomware writing encrypted files back to disk"
    severity = 3
    families = ["ransomware"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    def on_complete(self):
        droppedcount = 0

        for dropped in self.get_results("dropped", []):
            droppedtype = dropped["type"]
            droppedname = dropped["name"]
            filepath = dropped["filepath"]
            if droppedtype == "data" and ".tmp" not in droppedname:
                droppedcount += 1
                self.mark_ioc("file", filepath)
        if droppedcount > 50:
            if droppedcount > 1000:
                self.severity = 6
            elif droppedcount > 500:
                self.severity = 5
            elif droppedcount > 200:
                self.severity = 4
            return self.has_marks()
