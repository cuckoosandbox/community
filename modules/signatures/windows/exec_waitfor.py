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

class ExecWaitFor(Signature):
    name = "exec_waitfor"
    description = "WaitFor has been invoked (possibly to delay malicious activity)"
    severity = 2
    categories = ["script", "bypass"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        lower = "".join(self.get_command_lines()).lower()
        if "waitfor" in lower:
            cmdre = re.compile("waitfor \/t \d+")
            cmd = cmdre.search(lower)
            if cmd:
                self.mark_ioc("cmd", cmd.group(0))
            return True

