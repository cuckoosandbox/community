# Copyright (C) 2010-2021 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from lib.cuckoo.common.abstracts import Signature

class AntiAVWhitespace(Signature):
    name = "antiav_whitespace"
    description = "Additional whitespace added to commands to avoid string detection"
    severity = 2
    categories = ["anti-av"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"
    ttp = ["T1027"]

    indicator = "\s{10,}"

    def on_complete(self):
        for cmdline in self.get_command_lines():
            if re.search(self.indicator, cmdline):
                self.mark_ioc("cmdline", cmdline)
        return self.has_marks()
