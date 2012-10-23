# Copyright (C) 2012 Thomas "stacks" Birn (@stacksth)
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

import re

from lib.cuckoo.common.abstracts import Signature

class DisableTaskMgr(Signature):
    name = "disabletaskmgr"
    description = "Disables Windows' Task Manager"
    severity = 3
    categories = ["generic"]
    authors = ["Thomas Birn"]
    minimum = "0.4.2"

    def run(self, results):
        indicator = ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System"

        opened = False
        for key in results["behavior"]["summary"]["keys"]:
            regexp = re.compile(indicator, re.IGNORECASE)
            if regexp.match(key):
                opened = True

        if opened:
            for process in results["behavior"]["processes"]:
                for call in process["calls"]:
                    if call["category"] != "registry":
                        continue

                    for argument in call["arguments"]:
                        if argument["value"] == "DisableTaskMgr":
                            return True

        return False
