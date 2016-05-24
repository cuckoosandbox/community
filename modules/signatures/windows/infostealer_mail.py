# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class MailStealer(Signature):
    name = "infostealer_mail"
    description = "Harvests credentials from local email clients"
    severity = 3
    categories = ["infostealer"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Clients\\\\Mail.*",
        ".*\\\\Microsoft\\\\Windows\\ Messaging\\ Subsystem\\\\MSMapiApps.*",
        ".*\\\\Microsoft\\\\Windows\\ Messaging\\ Subsystem\\\\Profiles.*",
        ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Windows\\ Messaging\\ Subsystem\\\\Profiles.*",
        ".*\\\\Microsoft\\\\Office\\\\.*\\\\Outlook\\\\Profiles\\\\Outlook.*",
        ".*\\\\Microsoft\\\\Office\\\\Outlook\\\\OMI\\ Account\\ Manager\\\\Accounts.*",
        ".*\\\\Microsoft\\\\Internet\\ Account\\ Manager\\\\Accounts.*",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?IncrediMail.*"
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\ Live\\ Mail.*",
    ]

    files_re = [
        ".*\.pst$",
        ".*\\\\Microsoft\\\\Windows\\ Live\\ Mail.*",
        ".*\\\\Microsoft\\\\Address\\ Book\\\\.*\.wab$",
        ".*\\\\Microsoft\\\\Outlook\\ Express\\\\.*\.dbx$",
        ".*\\\\Foxmail\\\\mail\\\\.*\\\\Account\.stg$",
        ".*\\\\Foxmail.*\\\\Accounts\.tdat$",
        ".*\\\\Thunderbird\\\\Profiles\\\\.*\.default$",
        ".*\\\\AppData\\\\Roaming\\\\Thunderbird\\\\profiles.ini$",
    ]

    # To be replaced by a check_file(dirs=True) whenever we can do that in a
    # backwards compatible way. Even better if we can provide an ioc=True to
    # check_file() etc functions to return the IOC type for each result.
    file_actions = [
        "file_opened", "file_exists", "file_failed", "directory_enumerated",
    ]

    def on_complete(self):
        for indicator in self.files_re:
            for filepath in self.check_file(pattern=indicator, regex=True, all=True):
                self.mark_ioc("file", filepath)

        for indicator in self.regkeys_re:
            registry = self.check_key(pattern=indicator, regex=True)
            if registry:
                self.mark_ioc("registry", registry)

        return self.has_marks()
