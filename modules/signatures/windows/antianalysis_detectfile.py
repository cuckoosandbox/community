# Copyright (C) 2015 KillerInstinct, Updated 2016 for cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class AntiAnalysisDetectFile(Signature):
    name = "antiav_detectfile"
    description = "Attempts to identify installed analysis tools by a known file location"
    severity = 3
    categories = ["anti-analysis"]
    authors = ["KillerInstinct"]
    minimum = "2.0"

    file_indicators = [
         "^[A-Za-z]:\\\\analysis",
         "^[A-Za-z]:\\\\iDEFENSE",
         "^[A-Za-z]:\\\\popupkiller.exe$",
         "^[A-Za-z]:\\\\tools\\\\execute.exe$",
         "^[A-Za-z]:\\\\Program\\ Files(\\ \(x86\))?\\\\Fiddler",
         "^[A-Za-z]:\\\\ComboFix",
    ]

    def on_complete(self):
        for indicator in self.file_indicators:
            for match in self.check_file(pattern=indicator, regex=True, all=True):
                self.mark_ioc("file", match)

        return self.has_marks()
