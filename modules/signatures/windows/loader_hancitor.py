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

import base64
import re

from lib.cuckoo.common.abstracts import Signature

class Hancitor(Signature):
    name = "loader_hancitor"
    description = "Creates known Hancitor loader URLs and/or C2 request"
    severity = 3
    categories = ["loader"]
    families = ["hancitor"]
    authors = ["ronbarrey"]
    minimum = "2.0"

    urls_re = [
        ".*api.ipify.org",
        ".*com\/ls[0-9]\/.*.php",
        ".*ru\/ls[0-9]\/.*.php",
    ]

    c2_re = "^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})$"

    c2_xor_key = 122

    def on_complete(self):
        for procmem in self.get_results("procmemory", []):
            for url in procmem.get("urls", []):
                for indicator in self.urls_re:
                    match = self._check_value(pattern=indicator, subject=url,
                                              regex=True, all=all)
                    if match:
                        self.mark_ioc("url", url)

        for process in self.get_results("behavior", {}).get("processes", []):
            if not process["calls"]:
                for call in process["calls"]:
                    match = self._check_value(pattern=self.c2_re,
                                              subject=call.get("arguments",
                                                               {}).get(
                                                  "buffer", {}),
                                              regex=True, all=all)
                    if match:
                        decoded = base64.b64decode(match[0])
                        decrypted = ""
                        for ch in decoded:
                            decrypted += chr(ord(ch) ^ self.c2_xor_key)
                        c2 = re.findall("\{.*\}", decrypted)
                        if c2:
                            self.mark_ioc("c2", c2[0])

        return self.has_marks()
