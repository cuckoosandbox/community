# Copyright (C) 2018 Kevin Ross
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

class ATMDLLImport(Signature):
    name = "atm_dll_import"
    description = "Contains import to load an ATM specific DLL"
    severity = 2
    categories = ["atm", "static"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    atmimports = [
        "msxfs.dll",
        "xfs_conf.dll",
        "xfs_supp.dll",
    ]

    def on_complete(self):
        for imports in self.get_results("static", {}).get("pe_imports", []):
            dll = imports["dll"]
            for atmimport in self.atmimports: 
                if atmimport in dll.lower():
                    self.mark_ioc("dll_import", dll)

        return self.has_marks()
