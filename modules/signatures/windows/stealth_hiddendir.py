# Copyright (C) 2017 Cuckoo Sandbox
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re
from lib.cuckoo.common.abstracts import Signature

class StealthHiddenDir(Signature):
    name = "stealth_hidden_dir"
    description = "Creates a directory with a reserved system name so it is not accesible to users"
    severity = 3
    categories = ["stealth"]
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"

    filter_apinames = ["CreateDirectoryW", "NtCreateFile"]

    reserved_names = [
        "con", "prn", "nul", "lpt1", "lpt2", "lpt3", "lpt4",
        "lpt5", "lpt6", "lpt7", "lpt8", "lpt9", "com1", "com2",
        "com3", "com5", "com6", "com7", "com8", "com9", "godmode.",
        "administrative tools.", "all tasks.", "history."
    ]

    def on_call(self, call, process):
        path = None
        if "dirpath" in call["arguments"]:
            path = call["arguments"]["dirpath"]
        elif "filepath" in call["arguments"]:
            path = call["arguments"]["filepath"]

        if not path:
            return

        for name in self.reserved_names:
            pathre = re.compile(r"\\" + re.escape(name) + r"({|\\)")
            if pathre.search(path):
                self.mark_call()

        return self.has_marks()
