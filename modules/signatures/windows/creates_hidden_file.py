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

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.hidden_attrs = [2, 4]
        self.open_dispositions = [1, 3]

    def on_call(self, call, process):
        attr = call["arguments"]["file_attributes"]
        if attr in self.hidden_attrs:
             if call["api"] == "NtCreateFile":
                if call["arguments"]["create_disposition"] not in self.open_dispositions:
                    self.mark_call()
             else:
                self.mark_call()

    def on_complete(self):
        return self.has_marks()
