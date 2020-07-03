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

class P2PCnC(Signature):
    name = "p2p_cnc"
    description = "Communication to multiple IPs on high port numbers possibly indicative of a peer-to-peer (P2P) or non-standard command and control protocol"
    severity = 2
    categories = ["p2p", "cnc"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_analysistypes = set(["file"])

    ignoreports = [
        "5938",
        "9001",
        "9030",
        "9050",
        "9051",
        "9150",
        "9151",
    ]

    def on_complete(self):
        servers = []
        
        for tcp in self.get_results("network", {}).get("tcp", []):
            if tcp["dport"] > 1023 and tcp["dport"] not in self.ignoreports:
                if tcp["dst"] not in servers and not tcp["dst"].startswith(("0.", "127.", "169.254.", "10.", "220.", "224.", "239.", "240.", "172.16.", "192.168.", "255.255.255.255")):
                    servers.append(tcp["dst"])

        for udp in self.get_results("network", {}).get("udp", []):
            if udp["dport"] > 1023 and udp["dport"] not in self.ignoreports:
                if udp["dst"] not in servers and not udp["dst"].startswith(("0.", "127.", "169.254.", "10.", "220.", "224.", "239.", "240.", "172.16.", "192.168.", "255.255.255.255")):
                    servers.append(udp["dst"])

        if len(servers) > 4:
            for server in servers:
                self.mark_ioc("ip", server)

        return self.has_marks()
