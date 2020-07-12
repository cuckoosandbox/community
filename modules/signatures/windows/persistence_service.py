# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class PersistenceService(Signature):
    name = "persistence_service"
    description = "Creates a service, which may be used for persistence"
    severity = 2
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"

    def on_complete(self):
        for cmdline in self.get_command_lines():
            if "sc create" in cmdline:
                self.mark_ioc("cmdline", cmdline)

        return self.has_marks()
