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

class DirtJumper(Signature):
    name = "bot_dirtjumper"
    description = "Recognized to be a DirtJumper bot"
    severity = 3
    categories = ["bot", "ddos"]
    families = ["dirtjumper"]
    authors = ["nex"]

    def run(self, results):
        if results["network"]:
            for http in results["network"]["http"]:
                if http["method"] == "POST" and http["body"].startswith("k="):
                    self.data.append({"url" : http["uri"], "data" : http["body"]})
                    return True

        return False
