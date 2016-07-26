# Copyright (C) 2016 KillerInstinct, Updated 2016 For Cuckoo 2.0
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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class Kovter_APIs(Signature):
    name = "kovter_behavior"
    description = "Exhibits behavior characteristic of Kovter malware"
    severity = 3
    weight = 3
    categories = ["clickfraud", "downloader"]
    families = ["kovter"]
    authors = ["KillerInstinct"]
    minimum = "2.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastapi = str()
        self.chain = False
        self.kovterchain = False
        self.saw_large = False
        self.c2 = []

    filter_apinames = set(["CreateThread", "NtCreateSection", "LdrGetProcedureAddress", "NtSetValueKey", "RegSetValueExA", "RegSetValueExW"])

    def on_call(self, call, process):
        if call["api"] == "NtSetValueKey" or call["api"].startswith("RegSetValueEx"):
            vallen = len(call["arguments"]["value"])
            if vallen:
                length = int(vallen)
                if length > 16 * 1024:
                    self.saw_large = True

        continueChain = False
        if call["status"]:
            if call["api"] == "LdrGetProcedureAddress":
                resolved = call["arguments"]["function_name"]
                if resolved and resolved == "IsWow64Process":
                    continueChain = True

            elif call["api"] == "NtCreateSection":
                if self.lastapi == "LdrGetProcedureAddress" and self.chain:
                    attribs = call["arguments"]["section_name"]
                    if attribs and re.match("^[0-9A-F]{32}$", attribs):
                        continueChain = True

            elif call["api"] == "CreateThread":
                if self.lastapi == "NtCreateSection" and self.chain:
                    self.kovterchain = True

        self.chain = continueChain
        self.lastapi = call["api"]

    def on_complete(self):
        if self.kovterchain and self.saw_large:
            for procmem in self.get_results("procmemory", []):
                for url in procmem.get("urls", []):
                    if url.endswith(".php"):
                       if url not in self.c2:
                           self.c2.append(url)
                           self.mark_ioc("C2", url)
                    
        if self.kovterchain and self.saw_large and len(self.c2) > 0:
            return self.has_marks()
        elif self.kovterchain and self.saw_large:
            return True

        return False
