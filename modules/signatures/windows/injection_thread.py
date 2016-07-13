# Copyright (C) 2012-2016 JoseMi "h0rm1" Holguin (@j0sm1), Optiv, Inc. (brad.spengler@optiv.com), KillerInstinct
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

class InjectionThread(Signature):
    name = "injection_thread"
    description = "Code injection with CreateRemoteThread or NtQueueApcThread in a remote process"
    severity = 3
    categories = ["injection"]
    authors = ["JoseMi Holguin", "nex", "Optiv", "KillerInstinct"]
    minimum = "2.0"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None

    filter_apinames = [
        "OpenProcess",
        "NtOpenProcess",
        "NtMapViewOfSection",
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "NtWow64WriteVirtualMemory64",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "NtQueueApcThread",
    ]

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.sequence = 0
            self.process_handles = set()
            self.process_pids = set()
            self.handle_map = dict()
            self.lastprocess = process

        if call["api"] == "OpenProcess" and call["status"] == True:
            if call["arguments"]["process_id"] != process["pid"]:
                handle = call["return"]
                pid = str(call["arguments"]["process_id"])
                self.process_handles.add(handle)
                self.process_pids.add(pid)
                self.handle_map[handle] = pid
        elif call["api"] == "NtOpenProcess" and call["status"] == True:
            if call["arguments"]["process_identifier"] != process["pid"]:
                handle = call["arguments"]["process_handle"]
                pid = str(call["arguments"]["process_identifier"])
                self.process_handles.add(handle)
                self.process_pids.add(pid)
                self.handle_map[handle] = pid
        elif (call["api"] == "NtMapViewOfSection") and self.sequence == 0:
            if call["arguments"]["process_handle"] in self.process_handles:
                self.sequence = 2
        elif (call["api"] == "VirtualAllocEx" or call["api"] == "NtAllocateVirtualMemory") and self.sequence == 0:
            if call["arguments"]["process_handle"] in self.process_handles:
                self.sequence = 1
        elif (call["api"] == "NtWriteVirtualMemory" or call["api"] == "NtWow64WriteVirtualMemory64" or call["api"] == "WriteProcessMemory") and self.sequence == 1:
            if call["arguments"]["process_handle"] in self.process_handles:
                self.sequence = 2
        elif (call["api"] == "NtWriteVirtualMemory" or call["api"] == "NtWow64WriteVirtualMemory64"  or call["api"] == "WriteProcessMemory") and self.sequence == 2:
            handle = call["arguments"]["process_handle"]
            if handle in self.process_handles:
                addr = int(call["arguments"]["base_address"], 16)
                buf = call["arguments"]["buffer"]
                if addr >= 0x7c900000 and addr < 0x80000000 and buf.startswith("\\xe9"):
                    self.description = "Code injection via WriteProcessMemory-modified NTDLL code in a remote process"
                    #procname = self.get_name_from_pid(self.handle_map[handle])
                    #desc = "{0}({1}) -> {2}({3})".format(process["process_name"], str(process["pid"]),
                                                         #procname, self.handle_map[handle])
                    #self.mark_ioc("Injection", desc)
                    return True
        elif (call["api"] == "CreateRemoteThread" or call["api"].startswith("NtCreateThread")) and self.sequence == 2:
            handle = call["arguments"]["process_handle"]
            if handle in self.process_handles:
                #procname = self.get_name_from_pid(self.handle_map[handle])
                #desc = "{0}({1}) -> {2}({3})".format(process["process_name"], str(process["pid"]),
                                                     #procname, self.handle_map[handle])
                #self.mark_ioc("Injection", desc)
                return True
        elif call["api"].startswith("NtQueueApcThread") and self.sequence == 2:
            if str(call["arguments"]["process_id"]) in self.process_pids:
                self.description = "Code injection with NtQueueApcThread in a remote process"
                #desc = "{0}({1}) -> {2}({3})".format(self.lastprocess["process_name"], str(self.lastprocess["pid"]),
                                                     #process["process_name"], str(process["process_id"]))
                #self.mark_ioc("Injection", desc)
                return True

    #def on_complete(self):
        #return self.has_marks()
