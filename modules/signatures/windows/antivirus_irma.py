# Copyright (C) 2017 r00t0vi4
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

class IRMADetection(Signature):
    name = "antivirus_irma"
    description = "File has been identified by at least one AntiVirus engine on IRMA as malicious"
    severity = 3
    categories = ["antivirus"]
    authors = ["r00t0vi4"]
    minimum = "2.0"

    def on_complete(self):
        results = self.get_results("irma", {})
        status = results.get("status")
        if status == 1:
            for probe in results["probe_results"]:
                if probe["status"] == 1:
                    self.mark_ioc(probe["name"], probe["results"])

        return self.has_marks()
