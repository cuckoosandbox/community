# Copyright (C) 2018 Kevin Ross
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

class NetworkDNSTXTLookup(Signature):
    name = "network_dns_txt_lookup"
    description = "Performs a TXT record DNS lookup potentially for command and control or covert channel"
    severity = 3
    categories = ["dns", "cnc"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    whitelist = [
            "google.com",
            "abobe.com",
        ]

    def on_complete(self):
        for dns in self.get_results("network", {}).get("dns", []):
            is_whitelisted = False
            for whitelisted in self.whitelist:
                if whitelisted in dns["request"]:
                    is_whitelisted = True

            if not is_whitelisted:
                if dns["type"] == "TXT":
                    self.mark_ioc("domain", dns["request"])

        return self.has_marks()
