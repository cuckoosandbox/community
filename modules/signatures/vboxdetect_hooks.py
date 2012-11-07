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

class VBoxDetectHook(Signature):
    name = "vboxdetect_hook"
    description = "VirtualBox detection through module hooks"
    severity = 3
    categories = ["anti-vm"]
    authors = ["Anderson Tamborim"]
    minimum = "0.4.1"

    def run(self, results):
        for process in results["behavior"]["processes"]:
            for call in process["calls"]:
                for argument in call["arguments"]:
                    if argument["name"] == "FileName" and argument["value"] == "VBoxHook.dll":
                        return True
            return False
