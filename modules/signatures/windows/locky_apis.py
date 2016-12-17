# Copyright (C) 2016 KillerInstinct, Updated 2016 for Cuckoo 2.0
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

import hashlib
from urlparse import parse_qs, urlparse

from lib.cuckoo.common.abstracts import Signature

class Locky_APIs(Signature):
    name = "Locky_behavior"
    description = "Exhibits behavior characteristic of Locky ransomware"
    weight = 3
    severity = 3
    categories = ["ransomware"]
    families = ["locky"]
    authors = ["KillerInstinct"]
    minimum = "2.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.volumes = set()
        self.hashes = set()
        self.found = 0
        self.c2s = set()
        self.payment = set()
        self.keywords = ["id=", "act=", "lang="]
        self.sigchanged = False

    filter_apinames = set(["GetVolumeNameForVolumeMountPointW",
                           "InternetCrackUrlA", "CryptHashData"])

    def on_call(self, call, process):
        if call["api"] == "GetVolumeNameForVolumeMountPointW":
            if call["status"]:
                name = call["arguments"]["volume_name"]
                if name and len(name) > 10 and name not in self.volumes:
                    self.volumes.add(name)
                    md5 = hashlib.md5(name[10:-1]).hexdigest()[:16].upper()
                    self.hashes.add(md5)

        elif call["api"] == "CryptHashData":
            if self.hashes:
                buf = call["arguments"]["buffer"]
                if buf and all(word in buf for word in self.keywords):
                    # Try/Except handles when this behavior changes in the future
                    try:
                        args = parse_qs(urlparse("/?" + buf).query,
                                        keep_blank_values=True)
                    except:
                        self.sigchanged = True
                        self.severity = 1
                        self.description = "Potential Locky ransomware behavioral characteristics observed. (See Note)"
                        self.mark_ioc("Note", "Unexpected behavior observed for Locky. Please " \
                                                  "report this sample")

                    if args and "id" in args.keys():
                        if args["id"][0] in self.hashes:
                            self.found = process["pid"]
                        if "affid" in args:
                            self.mark_ioc("Affid", args["affid"][0])
                else:
                    check = re.findall(r"\s((?:https?://)?\w+(?:\.onion|\.tor2web)[/.](?:\w+\/)?)",
                                       buf, re.I)
                    if check:
                        for payment in check:
                            self.payment.add(payment)

        elif call["api"] == "InternetCrackUrlA":
            if self.found and process["pid"] == self.found:
                url = call["arguments"]["url"]
                if url and url.endswith(".php"):
                    self.c2s.add(url)

    def on_complete(self):
        if self.sigchanged:
            return self.has_marks()

        ret = False
        if self.found:
            ret = self.has_marks()
            if self.c2s:
                for c2 in self.c2s:
                    self.mark_ioc("C2", c2)

            if self.get_results("procmemory", []):
                dump_path = str()
                for process in self.get_results("procmemory", []):
                    if process["pid"] == int(self.found):
                        dump_path = process["file"]
                        break

                if dump_path:
                    with open(dump_path, "rb") as dump_file:
                        cData = dump_file.read()
                    buf = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3},[\d.,]+)\x00", cData)
                    if buf:
                        for c2 in buf.group(1).split(","):
                            self.mark_ioc("C2", c2)

            if self.payment:
                for url in self.payment:
                    self.mark_ioc("Payment", url)

        return ret
