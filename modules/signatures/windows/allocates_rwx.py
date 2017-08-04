# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AllocatesRWX(Signature):
    name = "allocates_rwx"
    description = "Allocates read-write-execute memory (usually to unpack itself)"
    severity = 2
    categories = ["unpacking"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "NtAllocateVirtualMemory", "NtProtectVirtualMemory"

    def on_call(self, call, process):
        if call["flags"]["protection"] == "PAGE_EXECUTE_READWRITE" and call["arguments"]["process_handle"].startswith("0xfffffff"):
            self.mark_call()

    def on_complete(self):
        return self.has_marks()

class AllocatesRWXRemoteProccess(Signature):
    name = "allocates_rwx_remote_process"
    description = "Allocates read-write-execute memory to another process indicating possible code injection"
    severity = 3
    categories = ["injection", "shellcode"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_apinames = "NtAllocateVirtualMemory", "NtProtectVirtualMemory"

    def on_call(self, call, process):
        if call["flags"]["protection"] == "PAGE_EXECUTE_READWRITE" and not call["arguments"]["process_handle"].startswith("0xfffffff"):
            self.mark_call()

    def on_complete(self):
        return self.has_marks()
