# Copyright (C) 2013 Claudio "nex" Guarnieri (@botherder)
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

class NetworkHTTP(Signature):
    name = "network_http"
    description = "Performs some HTTP requests"
    severity = 2
    categories = ["http"]
    authors = ["nex"]
    minimum = "2.0"

    host_safelist = [
        "www.msftncsi.com"
    ]

    def on_complete(self):
        for http in self.get_net_http():
            if http["host"].endswith(self.exclude_domain_tails):
                continue
            self.mark_ioc("request", "%s %s" % (http["method"], http["uri"]))
        for http in self.get_net_generic("https_ex"):
            if http["host"].endswith(self.exclude_domain_tails):
                continue
            self.mark_ioc("request", "%s %s://%s%s" % (
                http["method"], http["protocol"], http["host"], http["uri"],
            ))

        return self.has_marks()
