# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class RaisesException(Signature):
    name = "raises_exception"
    description = "One of the processes launched crashes"
    severity = 1
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        for stats in self.get_results("behavior", {}).get("apistats", {}).values():
            if "__exception__" in stats:
                return True
