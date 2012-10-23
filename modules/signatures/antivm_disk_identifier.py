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

class AntiVMDiskIdentifier(Signature):
    name = "antivm_disk_identifier"
    description = "Detects virtualization software with SCSI Disk Identifier trick"
    severity = 3
    categories = ["anti-vm"]
    authors = ["nex"]
    minimum = "0.4.1"

    def run(self, results):
        indicator_registry = "0x80000002"
        indicator_key = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"
        indicator_name = "Identifier"

        for process in results["behavior"]["processes"]:
            opened = False
            for call in process["calls"]:
                # First I check if the malware opens the releavant registry key.
                if call["api"].startswith("RegOpenKeyEx"):
                    # Store the number of arguments matched.
                    args_matched = 0
                    # Store the handle used to open the key.
                    handle = ""
                    for argument in call["arguments"]:
                        # Check if the registry is HKEY_LOCAL_MACHINE.
                        if argument["name"] == "Registry" and argument["value"] == indicator_registry:
                            args_matched += 1
                        # Check if the subkey opened is the correct one.
                        elif argument["name"] == "SubKey" and argument["value"] == indicator_key:
                            args_matched += 1
                        # Store the generated handle.
                        elif argument["name"] == "Handle":
                            handle = argument["value"]
                    
                    # If both arguments are matched, I consider the key to be successfully opened.
                    if args_matched == 2:
                        opened = True
                # Now I check if the malware verified the value of the key.
                elif call["api"].startswith("RegQueryValueEx"):
                    # Verify if the key was actually opened.
                    if not opened:
                        continue

                    # Verify the arguments.
                    args_matched = 0
                    for argument in call["arguments"]:
                        if argument["name"] == "Handle" and argument["value"] == handle:
                            args_matched += 1
                        elif argument["name"] == "ValueName" and argument["value"] == indicator_name:
                            args_matched += 1

                    # Finally, if everything went well, I consider the signature as matched.
                    if args_matched == 2:
                        return True

        return False
