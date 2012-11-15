# Copyright (C) 2012 JoseMi "h0rm1" Holguin (@j0sm1)
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

class InjectionCRT(Signature):
    name = "injection_createremotethread"
    description = "Code injection with CreateRemoteThread in a remote process"
    severity = 2
    categories = ["injection"]
    authors = ["JoseMi Holguin"]

    def run(self, results):
        for process in results["behavior"]["processes"]:
            sequence = 0
            process_handle = 0
            for call in process["calls"]:
                if call["api"]  == "OpenProcess" and sequence == 0:
                    for argument in call["arguments"]:
                        if argument["name"] == "ProcessId":
                            if argument["value"] != process["process_id"]:
                                sequence = 1
                                process_handle = call["return"]
                elif call["api"] == "VirtualAllocEx" and sequence == 1:
                    for argument in call["arguments"]:
                        if argument["name"] == "ProcessHandle" and argument["value"] == process_handle:
                            sequence = 2
                elif (call["api"] == "NtWriteVirtualMemory" or call["api"] == "WriteProcessMemory") and sequence == 2:
                    for argument in call["arguments"]:
                        if argument["name"] == "ProcessHandle" and argument["value"] == process_handle:
                            sequence = 3
                elif (call["api"] == "CreateRemoteThread"  or  call["api"] == "CreateRemoteThreadEx" ) and sequence == 3:
                    for argument in call["arguments"]:
                        if argument["name"] == "ProcessHandle" and argument["value"] == process_handle:
                            return True

        return False
