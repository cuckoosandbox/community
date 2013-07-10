# Copyright (C) 2012 Claudio "nex" Guarnieri (@botherder)
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

class DiskInformation(Signature):
    name = "antivm_generic_diskinfo"
    description = "Queries information on disks, possibly for anti-virtualization"
    severity = 3
    categories = ["anti-vm"]
    authors = ["nex"]
    minimum = "1.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None

    def event_apicall(self, call, process):
        indicators = [
            "scsi0",
            "physicaldrive0"
        ]

        if process != self.lastprocess:
            self.handle = None
            self.lastprocess = process

        if not self.handle:
            if call["api"] == "NtCreateFile":
                correct = False
                for argument in call["arguments"]:
                    if argument["name"] == "FileName":
                        for indicator in indicators:
                            if indicator in argument["value"].lower():
                                correct = True
                    elif argument["name"] == "FileHandle":
                        self.handle = argument["value"]

                if not correct:
                    self.handle = None
        else:
            if call["api"] == "DeviceIoControl":
                matched = 0
                for argument in call["arguments"]:
                    if argument["name"] == "DeviceHandle" and argument["value"] == self.handle:
                        matched += 1
                    elif argument["name"] == "IoControlCode" and argument["value"] == "2954240":
                        matched += 1

                if matched == 2:
                    return True
