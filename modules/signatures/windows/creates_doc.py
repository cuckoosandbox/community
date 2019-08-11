# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ntpath
import logging

from lib.cuckoo.common.abstracts import Signature

class CreatesDocument(Signature):
    name = "creates_doc"
    description = "Creates (office) documents on the filesystem"
    severity = 2
    categories = ["generic"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    pattern = ".*\\.(doc|docm|dotm|docx|ppt|pptm|pptx|potm|ppam|ppsm|xls|xlsm|xlsx|pdf)$"

    def on_complete(self):
        log = logging.getLogger(__name__)
        for fileopened in self.check_file(pattern=self.pattern, actions=["file_opened"], regex=True, all=True):
            opened_dirpath, opened_files = ntpath.split(fileopened)
        for filepath in self.check_file(pattern=self.pattern, actions=["file_written"], regex=True, all=True):
            file_dirpath, filepath_files = ntpath.split(filepath)
            if opened_dirpath == file_dirpath and filepath_files[2:] in opened_files and filepath_files[0:2] == "~$":
                if opened_dirpath == file_dirpath:
                    log.debug("Parameter 1 of 3: {} is equal to {}...Passed...".format(opened_dirpath, file_dirpath))
                    if filepath_files[2:] in opened_files:
                        log.debug("Parameter 2 of 3: {} is in {}...Passed...".format(filepath_files[2:], opened_files))
                        if filepath_files[0:2] == "~$":
                            log.debug("Parameter 3 of 3: {} is equal to ~$...Passed...Whitelisted...".format(filepath_files[0:2])) 
            else:
                self.mark_ioc("file", filepath)
        return self.has_marks()
