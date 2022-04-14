# Copyright (C) 2013 David Maciejak
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

class NetworkICMP(Signature):
    name = "network_icmp"
    description = "Generates some ICMP traffic"
    severity = 4
    categories = ["icmp"]
    authors = ["David Maciejak"]
    minimum = "2.0"

    def on_complete(self):
         icmp_traffic = self.get_net_icmp()
         if icmp_traffic:
             src = None
             network_sink = self.get_net_generic("dns_servers")
             for icmp_call in icmp_traffic:
                 # This will be the IP of the victim VM
                 if not src:
                    src = icmp_call["src"]

                # This will be either the IP of the victim VM or the IP of the
                #  machine it is trying to reach. We are interested in the latter.
                 dst = icmp_call["dst"]
                 if dst != src and dst not in network_sink:
                     self.mark_ioc("ip", dst)
         return self.has_marks()
