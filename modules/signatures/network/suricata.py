# Copyright (C) 2010-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import re
from lib.cuckoo.common.abstracts import Signature

dict = {
    'lokibot': 'loki'
}

class SuricataAlert(Signature):
    name = "suricata_alert"
    description = "Raised Suricata alerts"
    severity = 3
    categories = ["network"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):

        alerts = []

        for alert in self.get_results("suricata", {}).get("alerts", []):
                if alert["signature"] not in alerts:
                    if alert["signature"].startswith("ET TROJAN") or alert["signature"].startswith("ETPRO TROJAN"):

                        # extract text between parantheses
                        type = None
                        reg_type = re.search(r"\(([A-Za-z0-9_]+)\)", alert["signature"])
                        if reg_type is not None:
                            type = reg_type.group(1)

                        words = re.findall(r"[A-Za-z0-9]+", alert["signature"])
                        famcheck = words[2]
                        famchecklower = famcheck.lower()
                        if famchecklower == "win32" or famchecklower == "w32" or famchecklower == "ransomware":
                            famcheck = words[3]
                            famchecklower = famcheck.lower()

                        blacklist = [
                            "executable",
                            "potential",
                            "likely",
                            "rogue",
                            "supicious",
                            "generic",
                            "possible",
                            "known",
                            "common",
                            "troj",
                            "trojan",
                            "team",
                            "probably",
                            "w2km",
                            "http",
                            "abuse",
                            "win32",
                            "unknown",
                            "single",
                            "filename",
                            "worm",
                            "fake",
                            "malicious",
                            "observed",
                            "windows",
                        ]
                        isgood = True
                        for black in blacklist:
                            if black == famchecklower:
                                isgood = False
                                break
                        if len(famcheck) < 4:
                            isgood = False

                        if isgood:
                            if famchecklower in dict:
                                famchecklower = dict[famchecklower]

                            family = famchecklower.title()
                            self.mark_config({
                                "family": family,
                                "cnc": [
                                    alert["dst_ip"] + ":" + str(alert["dst_port"])
                                ],
                                "type": type
                            })

                        else:
                            self.mark_ioc("suricata", alert["signature"])

                    alerts.append(alert["signature"])
        return self.has_marks()
