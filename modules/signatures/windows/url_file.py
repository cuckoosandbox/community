# Copyright (C) 2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.cuckoo.common.abstracts import Signature

class URLFile(Signature):
    name = "url_file"
    description = "URLs have been extracted from an Internet shortcut file"
    authors = ["Cuckoo Technologies"]
    severity = 2
    categories = ["generic"]
    minimum = "2.0"

    def on_complete(self):
        target = self.get_results("target", {})
        if target.get("category") != "file":
            return

        targetfile = target.get("file", {})
        file_type = targetfile.get("type") or ""
        if "Internet shortcut" not in file_type:
            name, ext = os.path.splitext(targetfile.get("name", ""))
            if ext != ".url":
                return

        for url in targetfile.get("urls", []):
            self.mark_ioc("extracted URL", url)
        return self.has_marks()
