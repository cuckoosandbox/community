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

class CredentialDumpingLsass(Signature):
    name = "credential_dumping_lsass"
    description = "Locates and dumps memory from the lsass.exe process indicative of credential dumping"
    severity = 3
    categories = ["persistence", "lateral_movement"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    evented = True
    references = ["cyberwardog.blogspot.co.uk/2017/03/chronicles-of-threat-hunter-hunting-for_22.html", "cyberwardog.blogspot.co.uk/2017/04/chronicles-of-threat-hunter-hunting-for.html"]

    lsasspid = []
    lsasshandle = []
    creddump = False

    filter_apinames = "Process32NextW", "NtOpenProcess", "ReadProcessMemory",

    def on_call(self, call, process):
        if call["api"] == "Process32NextW":
            if call["arguments"]["process_name"] == "lsass.exe":
                self.lsasspid.append(call["arguments"]["process_identifier"])
                self.mark_call()

        if call["api"] == "NtOpenProcess":
            if call["arguments"]["process_identifier"] in self.lsasspid:
                if call["arguments"]["desired_access"] in ["0x00001010", "0x00001038"]:
                    self.lsasshandle.append(call["arguments"]["process_handle"])
                    self.mark_call()

        if call["api"] == "ReadProcessMemory":
            if call["arguments"]["process_handle"] in self.lsasshandle:
                self.creddump = True
                self.mark_call()

    def on_complete(self):
         if self.creddump:
             return self.has_marks()

class CredentialDumpingLsassAccess(Signature):
    name = "credential_dumping_lsass_access"
    description = "Requests access to read memory contents of lsass.exe potentially indicative of credential dumping"
    severity = 3
    categories = ["persistence", "lateral_movement"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    evented = True
    references = ["cyberwardog.blogspot.co.uk/2017/03/chronicles-of-threat-hunter-hunting-for_22.html", "cyberwardog.blogspot.co.uk/2017/04/chronicles-of-threat-hunter-hunting-for.html"]

    lsasspid = []
    creddump = False

    filter_apinames = "NtOpenProcess", "Process32NextW",

    def on_call(self, call, process):
        if call["api"] == "Process32NextW":
            if call["arguments"]["process_name"] == "lsass.exe":
                self.lsasspid.append(call["arguments"]["process_identifier"])
                self.mark_call()

        if call["api"] == "NtOpenProcess":
            if call["arguments"]["process_identifier"] in self.lsasspid:
                if call["arguments"]["desired_access"] in ["0x00001010", "0x00001038"]:
                    self.creddump = True
                    self.mark_call()

    def on_complete(self):
         if self.creddump:
             return self.has_marks()
