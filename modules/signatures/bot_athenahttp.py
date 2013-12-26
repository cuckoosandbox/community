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
import re

class AthenaHttp(Signature):
    name = "bot_athenahttp"
    description = "Recognized to be an Athena Http bot"
    severity = 3
    categories = ["bot", "ddos"]
    families = ["athenahttp"]
    authors = ["jjones"]
    minimum = "0.5"

    def run(self):
	athena_http_re = re.compile('a=(%[A-Fa-f0-9]{2})+&b=[-A-Za-z0-9+/]+(%3[dD])*&c=(%[A-Fa-f0-9]{2})+')
        if "network" in self.results:
            for http in self.results["network"]["http"]:
		print http
                if http["method"] == "POST" and athena_http_re.search(http["body"]):
                    self.data.append({"url" : http["uri"], "data" : http["body"]})
                    return True

        return False
