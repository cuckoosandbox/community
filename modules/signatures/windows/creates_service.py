# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class CreatesService(Signature):
    name = "creates_service"
    description = "Creates a service"
    severity = 2
    categories = ["service", "persistence"]
    authors = ["Cuckoo Technologies", "Kevin Ross"]
    minimum = "2.0"

    filter_apinames = [
        "CreateServiceA",
        "CreateServiceW",
        "StartServiceA", 
        "StartServiceW",
    ]

    servicehandles = []
    startedservicehandles = []   

    def on_call(self, call, process):
        if call["api"] == "CreateServiceA" or call["api"] == "CreateServiceW":
            self.servicehandles.append(call["arguments"]["service_handle"])
            self.mark_call()

        elif call["api"] == "StartServiceA" or call["api"] == "StartServiceW":
            handle = call["arguments"]["service_handle"]
            if handle in self.servicehandles:
                self.startedservicehandles.append(handle)
                self.mark_call()

    def on_complete(self):
        for handle in self.servicehandles:
            if handle not in self.startedservicehandles:
                self.description = "Created a service where a service was also not started"
                self.severity = 3

        return self.has_marks()
