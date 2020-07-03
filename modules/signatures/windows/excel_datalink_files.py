# Copyright (C) 2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.cuckoo.common.abstracts import Signature

class ExcelDataLinks(Signature):
    name = "excel_datalink"
    description = (
        "External resource URLs have been extracted from an Excel helper file"
    )
    authors = ["Cuckoo Technologies"]
    severity = 2
    categories = ["generic"]
    minimum = "2.0"

    extensions = ".iqy", ".slk"

    def on_complete(self):
        target = self.get_results("target", {})
        if target.get("category") != "file":
            return

        f = target.get("file", {})
        name, ext = os.path.splitext(f.get("name", ""))
        if ext not in self.extensions:
            return

        for url in f.get("urls", []):
            self.mark_ioc("Extracted URL", url)

        return self.has_marks()
