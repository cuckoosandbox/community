# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class VirtualPCDetect(Signature):
    name = "antivm_virtualpc"
    description = "Tries to detect VirtualPC"
    severity = 3
    categories = ["anti-vm"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    mutexes_re = [
        ".*MicrosoftVirtualPC7UserServiceMakeSureWe'reTheOnlyOneMutex",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            for mutex in self.check_mutex(pattern=indicator, regex=True, all=True):
                self.mark_ioc("mutex", mutex)

        return self.has_marks()
