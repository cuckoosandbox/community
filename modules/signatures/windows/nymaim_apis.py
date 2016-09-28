# Copyright (C) 2015 KillerInstinct, Updated 2016 for Cuckoo 2.0
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

import sys

from lib.cuckoo.common.abstracts import Signature

class Nymaim_APIs(Signature):
    name = "nymaim_behavior"
    description = "Exhibits behavior characteristic of Nymaim malware"
    weight = 3
    severity = 3
    categories = ["trojan", "ransomware"]
    families = ["nymaim"]
    authors = ["KillerInstinct"]
    minimum = "2.0"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.regkey = False
        self.keyname = str()

    filter_apinames = "NtCreateKey", "NtSetValueKey",

    def on_call(self, call, process):
        if call["api"] == "NtCreateKey":
            buf = call["arguments"]["regkey"]
            if buf and buf.startswith("HKEY_CURRENT_USER\\Software\\Microsoft\\") and buf.count("\\") == 3:
                self.keyname = buf
                self.mark_call()

        elif call["api"] == "NtSetValueKey":
            if self.keyname:
                buflen = sys.getsizeof(call["arguments"]["value"])
                key = call["arguments"]["regkey"]
                if buflen and buflen > 2048 and key.startswith(self.keyname):
                    self.regkey = True
                    self.mark_call()

    def on_complete(self):
        if self.regkey:
            return self.has_marks()
