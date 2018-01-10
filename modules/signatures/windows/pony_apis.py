# Copyright (C) 2015 KillerInstinct, Updated 2016 for cuckoo 2.0
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

import re
import string

from lib.cuckoo.common.abstracts import Signature

class Pony_APIs(Signature):
    name = "pony_behavior"
    description = "Exhibits behavior characteristic of Pony malware"
    weight = 3
    severity = 3
    categories = ["trojan", "infostealer"]
    families = ["pony"]
    authors = ["KillerInstinct"]
    minimum = "2.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.urls = set()

        self.badpid = str()
        self.guidpat = "\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}"
        self.whitelist = [
            "http://download.oracle.com/",
        ]

    filter_apinames = set(["RegSetValueExA", "InternetCrackUrlA"])

    def on_call(self, call, process):
        if call["api"] == "RegSetValueExA":
            buf = call["arguments"]["regkey"]
            if buf and "HWID" in buf:
                guid = call["arguments"]["value"]
                test = re.match(self.guidpat, guid)
                if test and not self.badpid:
                    self.badpid = str(process["pid"])

        elif call["api"] == "InternetCrackUrlA":
            if str(process["pid"]) == self.badpid:
                self.urls.add(call["arguments"]["url"])

        return None

    def on_complete(self):
        if self.badpid:
            if self.get_results("procmemory", []):
                dump_path = str()
                for process in self.get_results("procmemory", []):
                    if process["pid"] == int(self.badpid):
                        dump_path = process["file"]
                        break

                if dump_path:
                    with open(dump_path, "rb") as dump_file:
                        cData = dump_file.read()
                    # Get the aPLib header + data
                    buf = re.findall(r"aPLib .*PWDFILE", cData,
                                         re.DOTALL|re.MULTILINE)
                    # Strip out the header
                    if buf and len(buf[0]) > 200:
                        data = buf[0][200:]
                        output = re.findall("(https?:\/\/.+?(?:\.php|\.exe))",
                                            data)
                        if output:
                            for ioc in output:
                                if all(z in string.printable for z in ioc):
                                    for item in self.whitelist:
                                        if item not in ioc:
                                            self.mark_ioc("C2", ioc)

            if self.urls:
                for url in self.urls:
                    self.mark_ioc("C2", url)

        return self.has_marks()
