# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class CreatesDocument(Signature):
    name = "creates_doc"
    description = "Creates (office) documents on the filesystem"
    severity = 2
    categories = ["generic"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    pattern = ".*\\.(doc|docm|dotm|docx|ppt|pptm|pptx|potm|ppam|ppsm|xls|xlsm|xlsx|pdf)$"

    def on_complete(self):
        if self.get_results("target", {}).get("category") != "file":
            return

        f = self.get_results("target", {}).get("file", {})
        filename = f.get("name")
        if not filename:
            return

        for filepath in self.check_file(pattern=self.pattern, actions=["file_written"], regex=True, all=True):
            if filename not in filepath:
                self.mark_ioc("file", filepath)

        return self.has_marks()
