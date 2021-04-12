# Copyright (C) 2010-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class PUB_SERV_ABUSE(Signature):
    name = "public_service_abuse"
    description = "Abusing legit services for malware distribution"
    severity = 2
    categories = ["http"]
    authors = ["doomedraven"]
    minimum = "2.0"

    patterns = [
        ".*my.sharepoint.com.*",
        "https://www.evernote.com/shard/.+/sh/.+/res/.*",
        "https://docs.google.com/uc\\?authuser=\\d{1}&id=[\\w\\d]+&export=download",
        "https://onedrive.live.com/redir.aspx\\?cid=",
        "https://www.dropbox.com/l/scl/",
    ]

    def on_complete(self):
        urls = set()
        for http in self.get_net_http_ex():
            urls.add("%s://%s%s" % (
                    http["protocol"], http["host"], http["uri"]
                )
            )

        for pattern in self.patterns:
            for url in urls:
                url = re.match(pattern, url)
                if url:
                    self.mark_ioc("url", url.string)

        return self.has_marks()
