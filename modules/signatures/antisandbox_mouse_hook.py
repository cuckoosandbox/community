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

class HookMouse(Signature):
    name = "antisandbox_mouse_hook"
    description = "Installs an hook procedure to monitor for mouse events"
    severity = 3
    categories = ["hooking", "anti-sandbox"]
    authors = ["nex"]
    minimum = "0.5"

    def run(self):
        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if not call["api"].startswith("SetWindowsHookEx"):
                    continue

                arguments = 0
                for argument in call["arguments"]:
                    if argument["name"] == "HookIdentifier" and int(argument["value"]) in [7, 14]:
                        arguments += 1
                    elif argument["name"] == "ThreadId" and int(argument["value"]) == 0:
                        arguments += 1

                if arguments == 2:
                    return True

        return False
