# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AlinaFile(Signature):
    name = "alina_pos_file"
    description = "Created Known Alina POS Malware Files"
    severity = 3
    categories = ["pos"]
    authors = ["RedSocks"]
    minimum = "2.0"

    files_re = [
        ".*\\\\win-firewall.exe",
    ]

    def on_complete(self):
        for indicator in self.files_re:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("file", match)
                return True
