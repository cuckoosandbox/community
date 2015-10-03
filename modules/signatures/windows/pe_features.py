# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class PEFeatures(Signature):
    name = "pe_features"
    description = "The executable has PE anomalies (could be a false positive)"
    severity = 1
    categories = ["packer"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    section_names = [
        ".text", ".rdata", ".data", ".pdata", ".DATA", ".reloc", ".idata",
        ".rsrc", ".shared", ".bss", ".edata", ".tls", ".CRT", ".eh_fram",
        ".xdata",
    ]

    def on_complete(self):
        for section in self.get_results("static", {}).get("pe_sections", []):
            if section["name"] not in self.section_names:
                self.mark(section=section["name"])

        return self.has_marks()
