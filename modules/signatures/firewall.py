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

# Based on information from http://antivirus.about.com/od/windowsbasics/tp/autostartkeys.htm

import re

from lib.cuckoo.common.abstracts import Signature

class Firewall(Signature):
    name = "firewall"
    description = "Change Windows Firewall settings: This executable changes some settings of windows firewall"
    severity = 3
    categories = ["generic"]
    authors = ["Anderson Tamborim"]
    minimum = "0.4.1"

    def run(self, results):
        keys = [
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\SharedAccess\\\\Parameters\\\\*"
        ]

        for key in results["behavior"]["summary"]["keys"]:
            for indicator in keys:
                regexp = re.compile(indicator, re.IGNORECASE)
                if regexp.match(key):
                    self.data.append({"key" : key})
                    return True

        return False
