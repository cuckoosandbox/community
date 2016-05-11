# Copyright (C) 2016 Cuckoo Foundation. Kevin Ross, Will Metcalf, Brad Spengler. Code used from https://raw.githubusercontent.com/spender-sandbox/community-modified/master/modules/signatures/martians_ie.py
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class IEMartian(Signature):
    name = "ie_martian"
    description = "Internet Explorer creates one or more martian processes"
    severity = 3
    categories = ["martian", "exploit", "payload"]
    authors = ["Cuckoo Technologies", "Will Metcalf", "Kevin Ross"]
    minimum = "2.0"

    whitelist_re = [
        "\\\"C:\\\\\Program\\ Files(\\ \\(x86\\))?\\\\Internet\\ Explorer\\\\iexplore\\.exe\\\"\\ SCODEF:\\d+ CREDAT:\\d+$",
        "\\\"C\\:\\\\Program Files(?:\s\\(x86\\))?\\\\Adobe\\\\Reader\\ \\d+\\.\\d+\\\\Reader\\\\AcroRd32\\.exe\\\"\\ SCODEF:\\d+ CREDAT:\\d+$",
        "\\\"C\\:\\\\Program Files(?:\s\\(x86\\))?\\\\Java\\\\jre\\d+\\\\bin\\\\j(?:avaw?|p2launcher)\\.exe\\\"\\ SCODEF:\\d+ CREDAT:\\d+$",
        "\\\"C\\:\\\\Program Files(?:\s\\(x86\\))?\\\\Microsoft SilverLight\\\\(?:\\d+\\.)+\\d\\\\agcp.exe\\\"\\ SCODEF:\\d+ CREDAT:\\d+$",
        "\\\"C\\:\\\\Windows\\\\System32\\\\ntvdm\\.exe\\\"\\ SCODEF:\\d+ CREDAT:\\d+$",
        "\\\"C\\:\\\\Windows\\\\system32\\\\rundll32\\.exe\\\"\\ SCODEF:\\d+ CREDAT:\\d+$",
        "\\\"C\\:\\\\Windows\\\\syswow64\\\\rundll32\\.exe\\\"\\ SCODEF:\\d+ CREDAT:\\d+$",
        "\\\"C\\:\\\\Windows\\\\system32\\\\drwtsn32\\.exe\\\"\\ SCODEF:\\d+ CREDAT:\\d+$",
        "\\\"C\\:\\\\Windows\\\\syswow64\\\\drwtsn32\\.exe\\\"\\ SCODEF:\\d+ CREDAT:\\d+$",
        "\\\"C\\:\\\\Windows\\\\system32\\\\dwwin\\.exe\\\"\\ SCODEF:\\d+ CREDAT:\\d+$",
        "\\\"C\\:\\\\Windows\\\\system32\\\\WerFault\\.exe\\\"\\ SCODEF:\\d+ CREDAT:\\d+$",
        "\\\"C\\:\\\\Windows\\\\syswow64\\\\WerFault\\.exe\\\"\\ SCODEF:\\d+ CREDAT:\\d+$",
    ]

    def on_complete(self):
        for process in self.get_results("behavior", {}).get("generic", []):
            if process["process_name"] != "iexplore.exe":
                continue

            for cmdline in process.get("summary", {}).get("command_line", []):
                for regex in self.whitelist_re:
                    if re.match(regex, cmdline, re.I):
                        break
                else:
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()


class WscriptMartian(Signature):
    name = "wscript_martian"
    description = "Wscript.exe creates one or more martian processes"
    severity = 3
    categories = ["martian", "downloader"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    whitelist_re = [
        "\\\"C:\\\\\Windows\\\\System32\\\\wscript\\.exe\\\"\\ SCODEF:\\d+ CREDAT:\\d+$",
    ]

    def on_complete(self):
        for process in self.get_results("behavior", {}).get("generic", []):
            if process["process_name"] != "wscript.exe":
                continue

            for cmdline in process.get("summary", {}).get("command_line", []):
                for regex in self.whitelist_re:
                    if re.match(regex, cmdline, re.I):
                        break
                else:
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()
