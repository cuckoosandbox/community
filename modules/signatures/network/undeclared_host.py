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

import socket
from lib.cuckoo.common.abstracts import Signature

class HTTPBadHost(Signature):
    name = "http_bad_host"
    description = "HTTP Host header does not match the contacted IP"
    severity = 5
    categories = ["http"]
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"

    whitelist = [
        "2.21.246.24"
    ]

    def on_complete(self):
        for http in getattr(self, "get_net_http_ex", lambda: [])():
            if http["dst"] in self.whitelist:
                continue

            ips = socket.gethostbyname_ex(http["host"])[2]

            legit = False
            for ip in ips:
                if ip == http["dst"]:
                    legit = True

            if not legit:
                self.mark_ioc("HTTP Host", http["host"])
                self.mark_ioc("HTTP Host IP address", ip)
                self.mark_ioc("HTTP request real destination", http["dst"])

        return self.has_marks()

class HTTPRequestTamper(Signature):
    name = "http_host_tamper"
    description = "HTTP Host header was not DNS resolved (may indicate request tampering)"
    severity = 3
    categories = ["http"]
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"

    def on_complete(self):
        for http in getattr(self, "get_net_http_ex", lambda: [])():
            # HTTP Host was not DNS resolved
            if not self.check_domain(pattern=http["host"], regex=False, all=True):
                self.mark_ioc("request", "%s %s://%s%s" % (
                    http["method"], http["protocol"], http["host"], http["uri"],
                ))
                self.mark_ioc("Destination address", http["dst"])

        return self.has_marks()
