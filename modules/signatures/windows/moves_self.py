# Copyright (C) 2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class MovesSelf(Signature):
    name = "moves_self"
    description = "Moves the original executable to a new location"
    authors = ["Cuckoo Technologies"]
    severity = 2
    categories = ["stealth"]
    minimum = "2.0"

    filter_apinames = (
        "MoveFileWithProgressW", "MoveFileWithProgressTransactedW",
    )

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.initial_process = self.get_results("target", {}).get("file", {}).get("name", [])

    def on_call(self, call, process):
        oldpath = call["arguments"]["oldfilepath"]
        if self.initial_process in oldpath:
            self.mark_call()

    def on_complete(self):
        return self.has_marks()
