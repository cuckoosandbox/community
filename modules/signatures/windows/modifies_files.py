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

class ModifiesFiles(Signature):
    name = "modifies_files"
    description = "This sample modifies more than 5 files through " \
        "suspicious ways, likely a polymorphic virus or a ransomware"
    severity = 3
    minimum = "2.0"

    filter_apinames = "MoveFileWithProgressW",

    def on_call(self, call, process):
        self.mark_call()

    def on_complete(self):
        return self.has_marks(5)
