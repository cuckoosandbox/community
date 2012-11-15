# Copyright (C) 2012 Anderson Tamborim (@y2h4ck)
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

class VBoxDetectLibs(Signature):
    name = "antivm_vbox_libs"
    description = "Detects VirtualBox through the presence of a library"
    severity = 3
    categories = ["anti-vm"]
    authors = ["Anderson Tamborim"]
    minimum = "0.4.2"

    def run(self, results):
        for process in results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "LdrLoadDll":
                    for argument in call["arguments"]:
                        if (argument["name"] == "FileName" and 
                            "VBoxHook.dll" in argument["value"]):
                            return True

        return False
