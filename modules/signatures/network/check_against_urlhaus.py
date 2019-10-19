# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by Clevero (Marcel Caspar) - https://sittig.de
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class URLhaus(Signature):
    name = "check_domains_against_URLhaus"
    description = "Tries to contact a domain that was listed at URLhaus"
    severity = 5
    categories = ["dns"]
    authors = ["Marcel Caspar, Sittig Technologies GmbH"]
    minimum = "2.0"
   
    def on_complete(self):
        filepath = '/var/lib/peekaboo/urlhaus.txt'
        with open(filepath) as fp:
            line = fp.readline()
            while line:
                for match in self.check_domain(pattern=line.strip(), regex=True, all=True):
                    self.mark_ioc("domain", line.strip())
                    self.severity += 1
                line = fp.readline()

        return self.has_marks()
