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

class Fingerprint(Signature):
    name = "recon_fingerprint"
    description = "Collects information to fingerprint the system (MachineGuid, DigitalProductId, SystemBiosDate)"
    severity = 3
    categories = ["recon"]
    authors = ["nex"]
    minimum = "0.5"

    def run(self):
        indicators = [
            "MachineGuid",
            "DigitalProductId",
            "SystemBiosDate"
        ]

        threshold = 3
        matches = 0

        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["category"] != "registry":
                    continue

                for argument in call["arguments"]:
                    for indicator in indicators:
                        if argument["value"] == indicator:
                            indicators.remove(indicator)
                            matches += 1

        if matches >= threshold:
            return True

        return False
