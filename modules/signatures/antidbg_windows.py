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

class AntiDBGWindows(Signature):
    name = "antidbg_windows"
    description = "Checks for the presence of known windows from debuggers and forensic tools"
    severity = 3
    categories = ["anti-debug"]
    authors = ["nex"]
    minimum = "0.5"

    def run(self):
        indicators = [
            "OLLYDBG",
            "WinDbgFrameClass",
            "pediy06",
            "GBDYLLO",
            "FilemonClass",
            "PROCMON_WINDOW_CLASS",
            "File Monitor - Sysinternals: www.sysinternals.com",
            "Process Monitor - Sysinternals: www.sysinternals.com",
        ]

        for indicator in indicators:
            if self.check_argument(pattern=indicator, category="windows"):
                self.data.append({"window" : indicator})
                return True

        return False
