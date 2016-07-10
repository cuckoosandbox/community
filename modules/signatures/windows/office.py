# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

network_objects = [
    "microsoft.xmlhttp",
    "msxml2.serverxmlhttp",
    "msxml2.xmlhttp",
    "msxml2.serverxmlhttp.6.0",
    "winhttp.winhttprequest.5.1",
]

class OfficeCreateObject(Signature):
    name = "office_create_object"
    description = "Creates suspicious VBA object"
    severity = 3
    categories = ["vba"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "vbe6_CreateObject", "vbe6_GetObject"

    objects = {
        "adodb.stream": "file",
        "scripting.filesystemobject": "file",
        "shell.application": "process",
        "wscript.shell": "process",
    }

    # Include all globally defined network objects.
    objects.update(dict((_, "network") for _ in network_objects))

    descriptions = {
        "network": "May attempt to connect to the outside world",
        "file": "May attempt to write one or more files to the harddisk",
        "process": "May attempt to create new processes",
    }

    def on_call(self, call, process):
        objname = call["arguments"]["object_name"]
        if objname.lower() not in self.objects:
            return

        description = self.descriptions[self.objects[objname.lower()]]
        self.mark_ioc("com_class", objname, description)
        return True

class OfficeHttpRequest(Signature):
    name = "office_http_request"
    description = "Office document performs HTTP request (possibly to download malware)"
    severity = 5
    categories = ["vba"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "vbe6_Invoke",

    def on_call(self, call, process):
        # This checks if this instance method invocation belongs to
        # a known network class (e.g., "MSXML2.XMLHTTP").
        if call["flags"].get("this", "").lower() not in network_objects:
            return

        # The .Open method specifies the URL.
        if call["arguments"]["funcname"] != "Open":
            return

        # Usually ["GET", "url", False].
        if len(call["arguments"]["args"]) == 3:
            self.mark_ioc("payload_url", call["arguments"]["args"][1])
            return True

class OfficeRecentFiles(Signature):
    name = "office_recent_files"
    description = "Uses RecentFiles to determine whether it is running in a sandbox"
    severity = 4
    categories = ["vba"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "vbe6_Invoke",

    def on_call(self, call, process):
        if call["arguments"]["funcname"] == "RecentFiles":
            self.mark_call()
            return True

class HasOfficeEps(Signature):
    name = "has_office_eps"
    description = "Located potentially malicious Encapsulated Post Script (EPS) file"
    severity = 3
    categories = ["office"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        office = self.get_results("static", {}).get("office", {})
        if office.get("eps", []):
            return True

class OfficeEpsStrings(Signature):
    name = "office_eps_strings"
    description = "Suspicious keywords embedded in an Encapsulated Post Script (EPS) file"
    severity = 3
    categories = ["office"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    keywords = [
        "longjmp", "NtCreateEvent", "NtProtectVirtualMemory",
    ]

    def on_complete(self):
        office = self.get_results("static", {}).get("office", {})
        for s in office.get("eps", []):
            if s.strip() in self.keywords:
                self.mark_ioc("eps_string", s)

        return self.has_marks()
