# Copyright (C) 2010-2015 Cuckoo Foundation. Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class VMWareDetectFiles(Signature):
    name = "antivm_vmware_files"
    description = "Detects VMWare through the presence of various files"
    severity = 3
    categories = ["anti-vm"]
    authors = ["Cuckoo Technologies", "Optiv"]
    minimum = "2.0"

    files_re = [
        ".*vmmouse\\.sys",
        ".*vmhgfs\\.sys",
        ".*hgfs$",
        ".*vmci$",
        ".*\\\\VMware\\ Tools\\\\TPAutoConnSvc\.exe$",
        ".*\\\\VMware\\ Tools\\\\TPAutoConnSvc\.exe\.dll$",
        ".*\\\\Program\\ Files(\\ \(x86\))?\\\\VMware\\\\VMware\\ Tools.*",
    ]

    def on_complete(self):
        for indicator in self.files_re:
            for filepath in self.check_file(pattern=indicator, regex=True, all=True):
                self.mark_ioc("file", filepath)

        return self.has_marks()
