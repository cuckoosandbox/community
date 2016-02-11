# Copyright (C) 2010-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class RaisesException(Signature):
    name = "raises_exception"
    description = "One or more processes crashed"
    severity = 1
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "__exception__",

    def on_call(self, call, process):
        """Prettify the display of the call in the Signature."""
        call["raw"] = "stacktrace",
        call["arguments"]["stacktrace"] = \
            "\n".join(call["arguments"]["stacktrace"])

        self.mark_call()
        return True
