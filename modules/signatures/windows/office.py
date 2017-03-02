# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ntpath

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

class OfficeNetworkExe(Signature):
    name = "office_network_exe"
    description = "Office document has downloaded a PE file (possibly malware)"
    severity = 5
    categories = ["vba"]
    authors = "FDD @ Cuckoo Sandbox"
    minimum = "2.0"
    filter_apinames = "vbe6_Invoke"

    gets_response = False
    writes_disk   = False

    def on_call(self, call, process):
        if (call["arguments"]["funcname"] == "ResponseText" or
            call["arguments"]["funcname"] == "ResponseBody"):
            self.gets_response = True
            return

        if call["arguments"]["funcname"] != "Write":
            return

        buf = call["arguments"]["args"][0]
        if buf.startswith("MZ") and "This program cannot be run in DOS mode" in buf:
            self.writes_disk = True

    def on_complete(self):
        return gets_response and writes_disk

class OfficeWritesExe(Signature):
    name = "office_writes_exe"
    description = "Office document has written a PE file to disk"
    severity = 5
    categories = ["vba"]
    authors = "FDD @ Cuckoo Sandbox"
    minimum = "2.0"
    filter_apinames = "vbe6_Invoke"

    def on_call(self, call, process):
        if call["arguments"]["funcname"] == "Write":
            buf = call["arguments"]["args"][0]
            if (buf.startswith("MZ") and
                "This program cannot be run in DOS mode" in buf):
                self.mark_call()

        if call["arguments"]["funcname"] != "SaveToFile":
            filename = call["arguments"]["args"][0]
            self.mark_ioc("file", filename)
            self.mark_call()

        return self.has_marks()

class OfficeExec(Signature):
    name = "office_writes_exe"
    description = "Office document executes commands or files"
    severity = 5
    categories = ["vba"]
    authors = "FDD @ Cuckoo Sandbox"
    minimum = "2.0"
    filter_apinames = "vbe6_Invoke"

    def on_call(self, call, process):
        if (call["arguments"]["funcname"] != "Exec" and
            call["arguments"]["funcname"] != "Run"):
            return

        cmd = call["arguments"]["args"][0]
        self.mark_ioc("cmd", cmd)
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

class OfficeVulnerableGuid(Signature):
    name = "office_vuln_guid"
    description = "GUIDs known to be associated with a CVE were requested (may be False Positive)"
    severity = 3
    categories = ["office"]
    authors = ["Niels Warnars @ Cuckoo Technologies"]
    minimum = "2.0"

    bad_guids = {
        "BDD1F04B-858B-11D1-B16A-00C0F0283628": "CVE-2012-0158",
        "996BF5E0-8044-4650-ADEB-0B013914E99C": "CVE-2012-0158",
        "C74190B6-8589-11d1-B16A-00C0F0283628": "CVE-2012-0158",
        "9181DC5F-E07D-418A-ACA6-8EEA1ECB8E9E": "CVE-2012-0158",
        "1EFB6596-857C-11D1-B16A-00C0F0283628": "CVE-2012-1856",
        "66833FE6-8583-11D1-B16A-00C0F0283628": "CVE-2012-1856",
        "1EFB6596-857C-11D1-B16A-00C0F0283628": "CVE-2013-3906",
        "DD9DA666-8594-11D1-B16A-00C0F0283628": "CVE-2014-1761",
        "00000535-0000-0010-8000-00AA006D2EA4": "CVE-2015-0097",
        "0E59F1D5-1FBE-11D0-8FF2-00A0D10038BC": "CVE-2015-0097",
        "05741520-C4EB-440A-AC3F-9643BBC9F847": "CVE-2015-1641",
        "A08A033D-1A75-4AB6-A166-EAD02F547959": "CVE-2015-1641",
        "F4754C9B-64F5-4B40-8AF4-679732AC0607": "CVE-2015-1641",
        "4C599241-6926-101B-9992-00000B65C6F9": "CVE-2015-2424",
        "44F9A03B-A3EC-4F3B-9364-08E0007F21DF": "CVE-2015-2424",
    }

    def on_complete(self):
        summary = self.get_results("behavior", {}).get("summary", {})
        for guid in summary.get("guid", []):
            if guid.upper() in self.bad_guids:
                self.mark_ioc("cve", self.bad_guids[guid.upper()])
        return self.has_marks()

class OfficeVulnModules(Signature):
    name = "office_vuln_modules"
    description = "Libraries known to be associated with a CVE were requested (may be False Positive)"
    severity = 3
    categories = ["office"]
    authors = ["Niels Warnars @ Cuckoo Technologies"]
    minimum = "2.0"

    bad_modules = {
        "ogl.dll": "CVE-2013-3906",
        "oart.dll": "CVE-2013-3906",
        "packager.dll": "CVE-2014-4114/6352",
        "olkloadr.dll": "CVE-2015-1641",
        "epsimp32.flt": "CVE-2015-2545",
    }

    def on_complete(self):
        summary = self.get_results("behavior", {}).get("summary", {})
        for module in summary.get("dll_loaded", []):
            module = ntpath.split(module)[1]
            if module.lower() in self.bad_modules:
                self.mark_ioc("cve", self.bad_modules[module.lower()])
        return self.has_marks()
