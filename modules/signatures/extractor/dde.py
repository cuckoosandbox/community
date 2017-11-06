# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import xml.etree.ElementTree as ET

from cuckoo.common.abstracts import Extractor

ns = {
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
}

class OfficeDDE(Extractor):
    yara_rules = "OfficeDDE"
    minimum = "2.0.5"

    def handle_yara(self, filepath, match):
        root = ET.parse(filepath)

        elements = []
        for element in root.findall(".//w:instrText", ns):
            elements.append(element.text)

        cmdline = "".join(elements).strip()
        if cmdline.startswith(("DDE ", "DDEAUTO ")):
            cmdline = cmdline.split(None, 1)[1]

        self.push_command_line(cmdline)
