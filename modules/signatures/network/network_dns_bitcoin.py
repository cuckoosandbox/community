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

class NetworkDNSBitcoin(Signature):
    name = "network_dns_bitcoin"
    description = "DNS lookup of a Bitcoin blockchain or payment domain"
    severity = 2
    categories = ["bitcoin", "dns"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    references = ["https://howtobuybitcoins.info"]

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
        ".*\\.cex\\.io$",
        ".*\\.btcdirect\\.eu$",
        ".*\\.bitquick\\.co$",
        ".*\\.cashintocoins\\.com$",
        ".*\\.coinjar\\.com$",
        ".*\\.anxpro\\.com$",
        ".*\\.bittylicious\\.com$",
        ".*\\.btc-e\\.com$",
        ".*\\.coinbase\\.com$",
        ".*\\.quoine\\.com$",
        ".*\\.btcchina\\.com$",
        ".*\\.kraken\\.com$",
        ".*\\.bitfinex\\.com$",
        ".*\\.bitstamp\\.net$",
        ".*\\.anxbtc\\.com$",
        ".*\\.bitcurex\\.com$",
        ".*\\.ice3x\\.com$",
        ".*\\.itbit\\.com$",
        ".*\\.btcmarkets\\.com$",
        ".*\\.coinsetter\\.com$",
        ".*\\.hitbtc\\.com$",
        ".*\\.lakebtc\\.com$",
        ".*\\.therocktrading\\.com$",
        ".*\\.mercadobitcoin\\.com\\.br$",
        ".*\\.paymium\\.com$",
        ".*\\.clevercoin\\.com$",
        ".*\\.gatecoin\\.com$",
        ".*\\.coinspot\\.com\\.au$",
        ".*\\.crypto\\.bg$",
        ".*\\.exmo\\.com$",
        ".*\\.morrex\\.com$",
        ".*\\.mrcoin\\.eu$",
        ".*\\.ripio\\.com$",
        ".*\\.satoshitango\\.com$",
        ".*\\.satoshitango\\.com\\.ar$",
        ".*\\.vbtc\\.exchange$",
        ".*\\.shapeshift\\.io$",
        ".*\\.bitkonan\\.com$",
        ".*\\.bitmarket\\.pl$",
        ".*\\.campbx\\.com$",
        ".*\\.cavirtex\\.com$",
        ".*\\.coinfloor\\.co\\.uk$",
        ".*\\.fybse\\.se$",
        ".*\\.okcoin\\.com$",
        ".*\\.bitbay\\.net$",
        ".*\\.okcoin\\.cn$",
        ".*\\.bitcoin\\.co\\.id$",
        ".*\\.gocelery\\.com$",
        ".*\\.coinmate\\.io$",
        ".*\\.cryptopay\\.me$",
        ".*\\.bity\\.com$",
    ]

    def on_complete(self):
        for indicator in self.domains_re:
            for match in self.check_domain(pattern=indicator, regex=True, all=True):
                self.mark_ioc("domain", match)

        return self.has_marks()
