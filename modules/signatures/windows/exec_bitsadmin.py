# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import shlex
import yara
import logging
import traceback
import re

from lib.cuckoo.common.abstracts import Signature
from cuckoo.common.objects import URL_REGEX
from cuckoo.misc import cwd

log = logging.getLogger()

class ExecBitsAdmin(Signature):
    name = "exec_bits_admin"
    description = "BITSAdmin Tool has been invoked to download a file"
    severity = 3
    categories = ["script", "dropper"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        lower = "".join(self.get_command_lines()).lower()
        if "bitsadmin" in lower and "/download" in lower:
            cmdre = re.compile("bitsadmin .+ \/download .* (http:\/\/[^\s]+)")
            url = cmdre.search(lower)
            if url:
                self.mark_ioc("url", url.group(1))
            return True

