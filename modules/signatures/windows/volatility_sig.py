# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class VolFirewallStopped(Signature):
    name = "volatility_firewal_stopped"
    description = "Stopped Firewall service"
    severity = 3
    categories = ["generic"]
    authors = ["Thorsten Sick", "Sean Whalen"]
    minimum = "2.0"

    def on_complete(self):
        win7_or_higher = False
        shared_access_service_stopped = False
        modern_firewall_service_stopped = False
        shared_access_row = None
        modern_firewall_row = None
        for row in self.get_volatility("svcscan").get("data", []):
            if row["service_name"] == "SharedAccess":
                shared_access_row = row
                shared_access_service_stopped = True
            if row["service_name"] == "MpsSvc":
                win7_or_higher = True
                shared_access_row = row
                if row["service_state"] == "SERVICE_STOPPED":
                    modern_firewall_service_stopped = True
        if not win7_or_higher and shared_access_service_stopped ==True:
                self.mark_vol("stopped_service", service=shared_access_row)
        if modern_firewall_service_stopped:
            self.mark_vol("stopped_service", service=modern_firewall_row)

        return self.has_marks()

class VolALGStopped(Signature):
    name = "volatility_ALG_stopped"
    description = "Stopped Application Layer Gateway service"
    severity = 3
    categories = ["generic"]
    authors = ["Thorsten Sick", "Sean Whalen"]
    minimum = "2.0"

    def on_complete(self):
        win7_or_higher = False
        alg_service_stopped = False
        alg_row = None
        for row in self.get_volatility("svcscan").get("data", []):
            if row["service_name"] == "ALG":
                alg_row = row
                if row["service_state"] == "SERVICE_STOPPED":
                    alg_service_stopped = True
            if row["service_name"] == "MpsSvc":
                win7_or_higher = True
        if not win7_or_higher and alg_service_stopped == True:
                self.mark_vol("stopped_service", service=alg_row)

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
 is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
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
