# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from lib.cuckoo.common.abstracts import Signature

class PEFeatures(Signature):
    name = "pe_features"
    description = "The executable contains unknown PE section names indicative of a packer (could be a false positive)"
    severity = 1
    categories = ["packer"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"
    ttp = ["T1045"]

    section_names = [
        ".text", ".rdata", ".data", ".pdata", ".DATA", ".reloc", ".idata",
        ".rsrc", ".shared", ".bss", ".edata", ".tls", ".CRT", ".eh_fram",
        ".xdata", "UPX0", "UPX1", "UPX2",
    ]

    section_names_re = [
        "/[\\d]+$",
    ]

    def on_complete(self):
        for section in self.get_results("static", {}).get("pe_sections", []):
            if section["name"] in self.section_names:
                continue

            for section_name_re in self.section_names_re:
                if re.match(section_name_re, section["name"]):
                    break
            else:
                self.mark_ioc("section", section["name"])

        return self.has_marks()

class PEIDPacker(Signature):
    name = "peid_packer"
    description = "The executable uses a known packer"
    severity = 1
    categories = ["packer"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    ttp = ["T1045"]

    def on_complete(self):
        if self.get_results("static", {}).get("peid_signatures", []):
            for peid in self.get_results("static", {}).get("peid_signatures", []):
                self.mark_ioc("packer", peid)

        return self.has_marks()

class PEUnknownResourceName(Signature):
    name = "pe_unknown_resource_name"
    description = "The file contains an unknown PE resource name possibly indicative of a packer"
    severity = 1
    categories = ["packer"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    ttp = ["T1045"]

    names = [
        "RT_ACCELERATOR",
        "RT_ANICURSOR",
        "RT_ANIICON",
        "RT_BITMAP",
        "RT_CURSOR",
        "RT_DIALOG",
        "RT_DLGINCLUDE",
        "RT_FONT",
        "RT_FONTDIR",
        "RT_GROUP_CURSOR",
        "RT_GROUP_ICON",
        "RT_HTML",
        "RT_ICON",
        "RT_MANIFEST",
        "RT_MENU",
        "RT_MESSAGETABLE",
        "RT_PLUGPLAY",
        "RT_RCDATA",
        "RT_STRING",
        "RT_VERSION",
        "RT_VXD",
    ]

    def on_complete(self):
        for resource in self.get_results("static", {}).get("pe_resources", []):
            if resource["name"] not in self.names:
                self.mark_ioc("resource name", resource["name"])

        return self.has_marks()
