# Copyright (C) 2014 Brad Spengler.
# Copyright (C) 2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class CreatesHiddenFile(Signature):
    name = "creates_hidden_file"
    description = "Creates hidden or system file"
    authors = ["Cuckoo Technologies"]
    severity = 2
    categories = ["stealth"]
    minimum = "2.0"
    ttp = ["T1158"]
    filter_apinames = "NtCreateFile", "SetFileAttributesW"
    safelist = ["winword.exe"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.hidden_attrs = [2, 4]
        self.open_dispositions = [1, 3]
        self.filename = None
        self.temp_truncated_filename = None
        if self.get_results("target", {}).get("category") == "file":
            f = self.get_results("target", {}).get("file", {})
            self.filename = f.get("name")
            if len(self.filename) > 12:
                self.temp_truncated_filename = self.filename[-11:]

    def on_call(self, call, process):
        if process["process_name"].lower() in self.safelist:
            # Microsoft Word creates hidden temporary files to be used as backups.
            # These are false positives for this signature.
            # Their naming follows the convention \path\to\file\~$(substring of filename if length of filename > 12|filename)
            filepath = call["arguments"]["filepath"]
            if "~$" in filepath and \
                    ((self.temp_truncated_filename and self.temp_truncated_filename in filepath) or
                     (self.filename and self.filename in filepath)):
                # Definitely an FP
                return

        attr = call["arguments"]["file_attributes"]
        if attr in self.hidden_attrs:
             if call["api"] == "NtCreateFile":
                if call["arguments"]["create_disposition"] not in self.open_dispositions:
                    self.mark_call()
             else:
                self.mark_call()

    def on_complete(self):
        return self.has_marks()
