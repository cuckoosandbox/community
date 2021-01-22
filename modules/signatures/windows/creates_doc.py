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

        # Office files, when opened, create temporary backup files whose naming follows
        # the convention \path\to\file\~$(final 11 chars of filename if length of filename > 12|filename)
        # These files are false positives for this signature.
        temp_truncated_filename = None
        if len(filename) > 12:
            temp_truncated_filename = filename[-11:]

        for filepath in self.check_file(pattern=self.pattern, actions=["file_written"], regex=True, all=True):
            if filename in filepath or ("~$" in filepath and (temp_truncated_filename and temp_truncated_filename in filepath)):
                continue
            self.mark_ioc("file", filepath)

        return self.has_marks()
