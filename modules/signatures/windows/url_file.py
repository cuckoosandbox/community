# Copyright (C) 2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class URLFile(Signature):
    name = "url_file"
    description = "URLs have been extracted from an Internet shortcut file"
    authors = ["Cuckoo Technologies"]
    severity = 2
    categories = ["generic"]
    minimum = "2.0"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

        self.file = self.get_results("target", {}).get("file", {})

    def on_complete(self):
        if "Internet shortcut" not in self.file.get("type", ""):
            return
        if "urls" in self.file:
            urls = self.file.get("urls", [])
            for url in urls:
                self.mark_ioc("extracted URL", url)
            return self.has_marks()
