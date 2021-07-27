# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class MINERS(Signature):
    name = "cryptopool_domains"
    description = "Connects to crypto curency mining pool"
    severity = 10
    categories = ["miners"]
    authors = ["doomedraven"]
    minimum = "2.0.3"
    pool_domains = [
        "pool.minexmr.com",
        "pool.minergate.com",
        "opmoner.com",
        "crypto-pool.fr",
        "backup-pool.com",
        "monerohash.com",
        "poolto.be",
        "xminingpool.com",
        "prohash.net",
        "dwarfpool.com",
        "crypto-pools.org",
        "monero.net",
        "hashinvest.net",
        "moneropool.com",
        "xmrpool.eu",
        "ppxxmr.com",
        "alimabi.cn",
        "aeon-pool.com"
    ]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    def on_complete(self):

        for domain in self.pool_domains:
            if self.check_domain(domain):
                self.mark_ioc("host", domain)
                break

        return self.has_marks()
