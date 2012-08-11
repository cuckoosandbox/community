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

import re

from lib.cuckoo.common.abstracts import Signature

class BrowserStealer(Signature):
    name = "browserstealer"
    description = "Steals private information from local Internet browsers"
    severity = 3
    categories = ["infostealer", "http"]
    authors = ["nex"]
    minimum = "0.4.1"

    def run(self, results):
        indicators = [
            ".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\.default\\\\signons\\.sqlite\\Z(?ms)",
            ".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\.default\\\\secmod\\.db\\Z(?ms)",
            ".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\.default\\\\cert8\\.db\\Z(?ms)",
            ".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\.default\\\\key3\\.db\\Z(?ms)",
            ".*\\\\History\\\\History\\.IE5\\\\index\\.dat\\Z(?ms)",
            ".*\\\\Temporary\\ Internet\\ Files\\\\Content\\.IE5\\\\index\\.dat\\Z(?ms)",
            ".*\\\\Application\\ Data\\\\Google\\\\Chrome\\\\.*\\Z(?ms)",
            ".*\\\\Application\\ Data\\\\Chromium\\\\.*\\Z(?ms)",
            ".*\\\\Application\\ Data\\\\ChromePlus\\\\.*\\Z(?ms)",
            ".*\\\\Application\\ Data\\\\Nichrome\\\\.*\\Z(?ms)",
            ".*\\\\Application\\ Data\\\\Bromium\\\\.*\\Z(?ms)",
            ".*\\\\Application\\ Data\\\\RockMelt\\\\.*\\Z(?ms)"

        ]

        for file_name in results["behavior"]["summary"]["files"]:
            for indicator in indicators:
                regexp = re.compile(indicator)
                if regexp.match(file_name):
                    self.data.append({"file_name" : file_name})
                    return True

        return False
