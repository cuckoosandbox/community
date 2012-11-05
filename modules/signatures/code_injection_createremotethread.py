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

class CodeInjectionCreateRemoteThread(Signature):
    name = "code_injection_createremotethread"
    description = "Code injection with CreateRemoteThread in remote process"
    severity = 2
    alert = True
    categories = ["generic"]
    authors = ["JoseMi Holguin"]

    def run(self, results):
        for process in results["behavior"]["processes"]:
	    sequence = 0
            for mycall in process["calls"]:
		if mycall["api"]  == "OpenProcess" and sequence == 0:
			sequence = 1
			processhandle = mycall["return"]
		elif mycall["api"] == "VirtualAllocEx" and sequence == 1:
			for args in mycall["arguments"]:
				if args["name"] == "ProcessHandle" and args["value"] == processhandle:
					sequence = 2
		elif (mycall["api"] == "NtWriteVirtualMemory" or mycall["api"] == "WriteProcessMemory")  and sequence == 2:
			for args in mycall["arguments"]:
				if args["name"] == "ProcessHandle" and args["value"] == processhandle:
					sequence = 3
		elif (mycall["api"] == "CreateRemoteThread"  or  mycall["api"] == "CreateRemoteThreadEx" ) and sequence == 3:
			for args in mycall["arguments"]:
				if args["name"] == "ProcessHandle" and args["value"] == processhandle:
					return True

        return False
