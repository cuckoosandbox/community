# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class ProcMemDumpURLs(Signature):
    name = "memdump_urls"
    description = "Potentially malicious URLs were found in the process memory dump"
    severity = 2
    categories = ["unpacking"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        for procmem in self.get_results("procmemory", []):
            for url in procmem.get("urls", []):
                self.mark_ioc("url", url)

        return self.has_marks()

class ProcMemDumpTorURLs(Signature):
    name = "memdump_tor_urls"
    description = "Found URLs related to Tor in process memory dump (e.g. onion services, Tor2Web, and Ransomware)"
    severity = 3
    categories = ["unpacking", "ransomware", "c2"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    def on_complete(self):
        # List based on https://github.com/cuckoosandbox/community/blob/master/modules/signatures/network/network_torgateway.py
        indicators = [
            ".torproject.org",
            ".tor2web.",
            ".onion.",
            ".onion/",
            ".bortor.com",
            ".torpacho.com$",
            ".torsanctions.com",
            ".torwild.com",
            ".pay2tor.com",
            ".tor2pay.com",
            ".tor4pay.com",
            ".pay4tor.com",
            ".torexplorer.com",
            ".tor-gateways.de",
            ".torpaycash.com",
            ".torconnectpay.com",
            ".torwalletpay.com",
            ".walterwhitepay.com",
            ".rossulbrichtpay.com",
            ".42k2bu15.com",
            ".79fhdm16.com",
            ".myportopay.com",
            ".vivavtpaymaster.com",
            ".fraspartypay.com",
        ]

        for procmem in self.get_results("procmemory", []):
            for url in procmem.get("urls", []):
                for indicator in indicators:
                    if indicator in url or url.endswith(".onion"):
                        self.mark_ioc("url", url)

        return self.has_marks()

class ProcMemDumpIPURLs(Signature):
    name = "memdump_ip_urls"
    description = "Found URLs in memory pointing to an IP address rather than a domain (potentially indicative of Command & Control traffic)"
    severity = 3
    categories = ["unpacking", "c2"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    def on_complete(self):
        ip = re.compile("^(http|https)\:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        for procmem in self.get_results("procmemory", []):
            for url in procmem.get("urls", []):
                if re.match(ip, url):
                    self.mark_ioc("url", url)

        return self.has_marks()
