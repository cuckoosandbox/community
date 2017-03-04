# Copyright (C) 2010-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class NoLookupCommunication(Signature):
    name = "nolookup_communication"
    description = "Communicates with host for which no DNS query was performed"
    severity = 3
    categories = ["network"]
    authors = ["RicoVZ"]
    minimum = "2.0.0"

    def on_complete(self):
        address_types = ["A", "AAAA"]
        hosts = list(self.get_net_hosts())

        for query in self.get_net_generic("dns"):
            if query["type"] not in address_types:
                continue

            for ans in query["answers"]:
                if ans["data"] in hosts:
                    hosts.remove(ans["data"])

        if len(hosts) > 0:
            for host in hosts:
                if host not in self.get_net_generic("dns_servers"):
                    self.mark(host=host)

        return self.has_marks()
