# Copyright (C) 2012 Claudio "nex" Guarnieri (@botherder)
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

class AntiVMServices(Signature):
    name = "antivm_generic_services"
    description = "Enumerates services, possibly for anti-virtualization"
    severity = 3
    categories = ["anti-vm"]
    authors = ["nex"]
    minimum = "0.5"

    def run(self):
        for process in self.results["behavior"]["processes"]:
            handle = None
            for call in process["calls"]:
                if not handle:
                    if call["api"].startswith("RegOpenKeyEx"):
                        correct = False
                        for argument in call["arguments"]:
                            if argument["name"] == "SubKey":
                                if argument["value"] == "SYSTEM\\ControlSet001\\Services":
                                    correct = True
                            elif argument["name"] == "Handle":
                                handle = argument["value"]

                        if not correct:
                            handle = None
                else:
                    if call["api"].startswith("RegEnumKeyEx"):
                        for argument in call["arguments"]:
                            if argument["name"] == "Handle" and argument["value"] == handle:
                                return True

        return False
