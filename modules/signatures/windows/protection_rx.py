# Copyright (C) 2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class MemoryProtectionRX(Signature):
    name = "protection_rx"
    description = "Changes read-write memory protection to read-execute (probably to"
    description += " avoid detection when setting all RWX flags at the same time)"
    authors = ["Cuckoo Technologies"]
    severity = 2
    categories = ["unpacking"]
    minimum = "2.0"

    filter_apinames = (
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
        "VirtualAllocEx", "VirtualProtectEx"
    )

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.allocated_addresses = []
        self.alloc_apis = ["VirtualAllocEx", "NtAllocateVirtualMemory"]
        self.protect_apis = ["NtProtectVirtualMemory", "VirtualProtectEx"]
        self.write_constants = "PAGE_READWRITE", "PAGE_EXECUTE_WRITECOPY", "PAGE_WRITECOPY"
        self.execute_constants = "PAGE_EXECUTE_WRITECOPY", "PAGE_EXECUTE_READ", "PAGE_EXECUTE"

    def on_call(self, call, process):
        prot = call["flags"]["protection"]
        api = call["api"]
        addr = call["arguments"]["base_address"]
        if api in self.alloc_apis and prot in self.write_constants:
            self.allocated_addresses.append(addr)
        elif api in self.protect_apis and prot in self.execute_constants:
            if addr in self.allocated_addresses:
                self.mark_call()
                return True
