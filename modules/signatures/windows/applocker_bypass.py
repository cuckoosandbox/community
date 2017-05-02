# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import shlex
import yara
import logging
import traceback
import re

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger()

class AppLockerBypass(Signature):
    name = "applocker_bypass"
    description = "Powershell script bypasses AppLocker by calling regsvr32"
    severity = 3
    categories = ["applocker", "bypass"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        for cmdline in self.get_command_lines():
            lower = cmdline.lower()
            script, args = None, shlex.split(cmdline)

            for idx, arg in enumerate(args):
                script = None
                # If command is b64 encoded
                enccmdre = re.compile("\-[e^]{1,2}[ncodema^]+")
                if enccmdre.search(lower):
                    try:
                        script = args[idx+1].decode("base64").decode("utf16")
                    except Exception as e:
                        pass

                if script:
                    bypassre = re.compile("regsvr32[^;]+\/i:" \
                            "(https?|ftp):\/\/[^\s\/$.?#].[^\s\"']+[\s]+\w+\.dll")
                    m = bypassre.search(script)
                    if m:
                        self.mark_ioc("cmd", m.group(0))
                        break

        return self.has_marks()
