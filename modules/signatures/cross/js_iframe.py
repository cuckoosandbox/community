# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from lib.cuckoo.common.abstracts import Signature

class JsIframe(Signature):
    name = "js_iframe"
    description = "Dynamically creates an iframe element"
    severity = 3
    categories = ["obfuscation"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "CIFrameElement_CreateElement",

    safelist = [
        "https?://googleads\\.g\\.doubleclick\\.net/pagead/",
        "https?://ad\\.doubleclick\\.net/ddm/",
    ]

    def on_call(self, call, process):
        iframe = call["arguments"].get("attributes", {}).get("src")
        if not iframe:
            return

        for safelist in self.safelist:
            if re.match(safelist, iframe):
                return

        self.mark_call()
        return True
