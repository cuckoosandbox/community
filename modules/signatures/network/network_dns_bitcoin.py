# Copyright (C) 2017 Kevin Ross
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

class NetworkDNSBlockchain(Signature):
    name = "network_dns_blockchain"
    description = "DNS lookup of a Bitcoin blockchain or node domain"
    severity = 2
    categories = ["bitcoin", "dns"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    domains_re = [
        ".*\\.blockchain\\.com$",
        ".*\\.blockchain\\.info$",
        ".*\\.blockcypher\\.com$",
        ".*\\.blockr\\.io$",
        ".*\\.bitaps\\.com$",
        ".*\\.chain\\.so$",
        ".*\\.bitpay\\.com$",
        ".*\\.blocktrail\\.com$",
        ".*\\.statoshi\\.info$",
        ".*\\.bitcoinwisdom\\.com$",
        ".*\\.tradeblock\\.com$",
        ".*\\.blockseer\\.com$",
        ".*\\.nodecounter\\.com$",
        ".*\\.bitnodes\\.21\\.co$",
        ".*\\.coin\\.dance$",
    ]

    def on_complete(self):
        for indicator in self.domains_re:
            for match in self.check_domain(pattern=indicator, regex=True, all=True):
                self.mark_ioc("domain", match)

        return self.has_marks()
