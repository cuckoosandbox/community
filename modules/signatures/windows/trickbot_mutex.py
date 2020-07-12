# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class TrickbotMutexes(Signature):
    name = "trickbot_mutexes"
    description = "Trickbot mutex has been observed"
    severity = 3
    categories = ["banker"]
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"

    mutexes_re = [
        "Global\\TrickBot",
        "Global\\MGlob"
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            mutex = self.check_mutex(pattern=indicator, regex=False)
            if mutex:
                self.mark_ioc("mutex", mutex)

        return self.has_marks()
