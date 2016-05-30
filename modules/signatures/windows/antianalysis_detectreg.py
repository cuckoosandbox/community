# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com), Updated 2016 For Cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AntiAnalysisDetectReg(Signature):
    name = "antianalysis_detectreg"
    description = "Attempts to identify installed analysis tools by registry key"
    severity = 3
    categories = ["anti-analysis"]
    authors = ["Optiv"]
    minimum = "2.0"

    reg_indicators = [
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\App\\ Paths\\\\Wireshark\.exe$",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\Wireshark$",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\App\\ Paths\\\\Fiddler\.exe$",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\App\\ Paths\\\\Fiddler2\.exe$",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\Fiddler2$",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Fiddler2$",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\SOFTWARE\\\\IEInspectorSoft.*",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\IEHTTPAnalyzer\.HTTPAnalyzerAddon$",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\IEHTTPAnalyzerStd\.HTTPAnalyzerStandAlone$",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\Charles\.AMF\.Document$",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?XK72\\ Ltd\\ folder$",
    ]

    def on_complete(self):
        for indicator in self.reg_indicators:
            for regkey in self.check_key(pattern=indicator, regex=True, all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()
