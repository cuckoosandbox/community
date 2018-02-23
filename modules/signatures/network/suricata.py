# Copyright (C) 2015-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from lib.cuckoo.common.abstracts import Signature

mapping = {
    "lokibot": "loki",
}

# Obviously needs some more work.
protocols = {
    80: "http",
    443: "https",
}

class SuricataAlert(Signature):
    name = "suricata_alert"
    description = "Raised Suricata alerts"
    severity = 3
    categories = ["network"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    et_trojan = "ET TROJAN", "ETPRO TROJAN"
    blacklist = (
        "executable", "potential", "likely", "rogue", "supicious", "generic",
        "possible", "known", "common", "troj", "trojan", "team", "probably",
        "w2km", "http", "abuse", "win32", "unknown", "single", "filename",
        "worm", "fake", "malicious", "observed", "windows", "flashpoint",
        "msil"
    )
    family_next = (
        "win32", "win64", "w32", "ransomware", "backdoor"
    )

    def extract_family(self, signature):
        # Extract research lab between square brackets []
        res_lab = re.search("\[([A-Za-z0-9])+\]", signature)
        res_lab = res_lab.group(0) if res_lab else None
        # Remove research lab from signature, to get family extracted in the next lines
        if res_lab:
            signature = signature.replace(res_lab, "")

        words = re.findall("[A-Za-z0-9_]+", signature)
        if len(words) < 3:
            return

        family = words[2].lower()
        if family in self.family_next and len(words) > 3:
            family = words[3].lower()

        if family in self.blacklist or len(family) < 4:
            return

        # If it exists in our mapping, normalize the name.
        return mapping.get(family, family)

    def on_complete(self):
        alerts = []
        for alert in self.get_results("suricata", {}).get("alerts", []):
            if alert["signature"] in alerts:
                continue
            if not alert["signature"].startswith(self.et_trojan):
                continue

            # Extract text between parentheses.
            reg_type = re.search("\\(([A-Za-z0-9_]+)\\)", alert["signature"])
            reg_type = reg_type.group(1) if reg_type else None

            family = self.extract_family(alert["signature"])
            if not family:
                continue

            self.mark_config({
                "family": family.title(),
                "cnc": "%s://%s:%s" % (
                    protocols.get(alert["dst_port"], "tcp"),
                    alert["dst_ip"], alert["dst_port"]
                ),
                "type": reg_type,
            })

            self.mark_ioc("suricata", alert["signature"])
            alerts.append(alert["signature"])
        return self.has_marks()
