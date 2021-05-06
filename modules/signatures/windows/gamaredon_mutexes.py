# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class GamaredonMutexes(Signature):
    name = "gamaredon_mutexes"
    description = "Gamaredon APT mutex has been observed"
    severity = 3
    categories = ["apt", "mutex"]
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"

    mutexes_re = [
        "asassin1dj", "IESQMMUTEX_0_208", "__Wsnusb73__", "__Wsnusbtt73__",
        "qpoly67l8"
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            mutex = self.check_mutex(pattern=indicator, regex=False)
            if mutex:
                self.mark_ioc("mutex", mutex)

        return self.has_marks()