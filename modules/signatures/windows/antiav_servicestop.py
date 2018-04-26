# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com), Updated 2016 for Cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class AntiAVServiceStop(Signature):
    name = "antiav_servicestop"
    description = "Attempts to stop active services"
    severity = 3
    categories = ["anti-av"]
    authors = ["Optiv"]
    minimum = "2.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.handles = dict()
        self.lastprocess = 0
        self.stoppedservices = []

    filter_apinames = set(["OpenServiceW", "OpenServiceA", "ControlService"])

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.handles = dict()
            self.lastprocess = process

        if (call["api"] == "OpenServiceA" or call["api"] == "OpenServiceW") and call["status"]:
            handle = call["arguments"]["service_handle"]
            self.handles[handle] = call["arguments"]["service_name"]
        elif call["api"] == "ControlService":
            handle = call["arguments"]["service_handle"]
            code = call["arguments"]["control_code"]
            if code == 1 and handle in self.handles and self.handles[handle] not in self.stoppedservices:
                self.stoppedservices.append(self.handles[handle])
                self.mark_call()

    def on_complete(self):
        if self.stoppedservices:
            return self.has_marks()
