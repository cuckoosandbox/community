# Copyright (C) 2017 Kevin Ross
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

try:
    import re2 as re
except ImportError:
    import re

class OfficeEnableContentOCR(Signature):
    name = "office_enable_content_ocr"
    description = "Displays a possible message to user in office asking them to enable macro content (check screenshots)"
    severity = 3
    categories = ["macro", "downloader", "office", "ocr"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

        self.indicators = [
            "enable macro",
            "enable content",
            "enable editing"
        ]

    def on_complete(self):
        for screenshot in self.get_results("screenshots", []):
            if "ocr" in screenshot:
                ocr = screenshot["ocr"].lower()
                patterns = "|".join(self.indicators)
                if len(re.findall(patterns, ocr)) > 0:
                    self.mark_ioc("message", ocr)

        return self.has_marks()
