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

class DllLoadUncommonFileTypes(Signature):
    name = "dll_load_uncommon_file_types"
    description = "A file with an unusual extension was attempted to be loaded as a DLL."
    severity = 3
    categories = ["dll"]
    minimum = "2.0"
    ttp = ["T1574"]

    indicator = ".+\.(?!dll).{1,4}$"
    safelist = [
        "winspool.drv",
        "C:\Python27\DLLs\_socket.pyd",
        "C:\Program Files (x86)\Adobe\Reader 11.0\Reader\plug_ins\Annots.api",
    ]

    def on_complete(self):
        dll = self.check_dll_loaded(pattern=self.indicator, regex=True)
        if dll and dll not in self.safelist:
            self.mark_ioc("dll", dll)

        return self.has_marks()