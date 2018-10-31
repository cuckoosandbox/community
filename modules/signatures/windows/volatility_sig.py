# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class VolFirewallStopped(Signature):
    name = "volatility_firewal_stopped"
    description = "topped Firewall service"
    severity = 3
    categories = ["generic"]
    authors = ["Thorsten Sick", "Sean Whalen"]
    minimum = "2.0"

    def on_complete(self):
        win7_or_higher = False
        shared_access_service_stopped = False
        modern_firewall_service_stopped = False
        for row in self.get_volatility("svcscan").get("data", []):
            if row["service_name"] == "SharedAccess" and row["service_state"] == "SERVICE_STOPPED":
                shared_access_service_stopped = True
            if row["service_name] == "MpsSvc":
                win7_or_higher = True
                if rew["service_state] == "SERVICE_STOPPED":
                    modern_firewall_service_stopped = True
        if (not win7_or_higher and shared_access_service_stopped ==True) or modern_windows_firewall_stopped:
            self.mark_vol("stopped_service", service=row)

        return self.has_marks()

class SecurityCenterStopped(Signature):
    name = "volatility_security_center_stopped"
    description = "Stopped Security Center service"
    severity = 3
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    minimum = "2.0"

    def on_complete(self):
        for row in self.get_volatility("svcscan").get("data", []):
            if row["service_name"] == "wscsvc" and \
                    row["service_state"] == "SERVICE_STOPPED":
                self.mark_vol("stopped_service", service=row)

        return self.has_marks()


class VolHandles1(Signature):
    name = "volatility_handles_1"
    description = "One or more thread handles in other processes"
    severity = 2
    categories = ["generic"]
    authors = ["Thorsten Sick"]
    minimum = "2.0"

    def on_complete(self):
        threads = set()

        for row in self.get_volatility("handles").get("data", []):
            if row["handle_type"] == "Thread":
                w1, t1, w2, p1 = row["handle_name"].split(" ")
                if int(p1) != row["process_id"]:
                    threads.add("%d -> %s/%s" % (row["process_id"], p1, t1))

        if threads:
            self.mark_vol("injections", threads=list(threads))

        return self.has_marks()
