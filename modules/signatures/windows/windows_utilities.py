# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class UsesWindowsUtilities(Signature):
    name = "uses_windows_utilities"
    description = "Uses Windows utilities for basic Windows functionality"
    severity = 2
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    utilities = [
        "tasklist",
        "taskkill",
        "netsh",
        "netstat",
        "bitsadmin",
        "attrib",
    ]

    def on_complete(self):
        for cmdline in self.get_command_lines():
            for utility in self.utilities:
                if utility in cmdline.lower():
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()

class ModifiesFileACLs(Signature):
    name = "modifies_file_acls"
    description = "Uses Windows utilities to modify file/folder permissions"
    severity = 3
    authors = ["Kevin Ross"]
    minimum = "2.0"

    utilities = [
        "cacls",
        "icalcs",
        "xcalcs",
    ]

    def on_complete(self):
        for cmdline in self.get_command_lines():
            for utility in self.utilities:
                if utility in cmdline.lower():
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()
