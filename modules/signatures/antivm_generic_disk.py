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
    minimum = "0.5"

    def run(self):
        indicators = [
            "scsi0",
            "physicaldrive0"
        ]

        for process in self.results["behavior"]["processes"]:
            handle = None
            for call in process["calls"]:
                if not handle:
                    if call["api"] == "NtCreateFile":
                        correct = False
                        for argument in call["arguments"]:
                            if argument["name"] == "FileName":
                                for indicator in indicators:
                                    if indicator in argument["value"].lower():
                                        correct = True
                            elif argument["name"] == "FileHandle":
                                handle = argument["value"]

                        if not correct:
                            handle = None
                else:
                    if call["api"] == "DeviceIoControl":
                        matched = 0
                        for argument in call["arguments"]:
                            if argument["name"] == "DeviceHandle" and argument["value"] == handle:
                                matched += 1
                            elif argument["name"] == "IoControlCode" and argument["value"] == "2954240":
                                matched += 1

                        if matched == 2:
                            return True

        return False
