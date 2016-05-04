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

class RamsomwareDroppedFiles(Signature):
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
            if droppedtype == "data" and ".tmp" not in droppedname:
                droppedcount += 1
        if droppedcount > 50:
            if droppedcount > 1000:
                self.severity = 6
            elif droppedcount > 500:
                self.severity = 5
            elif droppedcount > 200:
                self.severity = 4
            return True
