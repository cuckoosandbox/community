# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class MaliciousDocumentURLs(Signature):
    name = "malicious_document_urls"
    description = "Potentially malicious URL found in document"
    severity = 3
    categories = ["downloader"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = [
        "InternetCrackUrlW",
    ]

    filter_analysistypes = "file",

    def on_call(self, call, process):
        if process["process_name"].lower() == "wscript.exe":
            self.mark_ioc("url", call["arguments"]["url"])

    def on_complete(self):
        return self.has_marks()
    
class DocumentLoadedFlash(Signature):
    name = "document_loaded_flash"
    description = "A document file loaded Flash indicative of an exploit attempt"
    severity = 3
    categories = ["exploit"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.pname = []

    proc_list = [
        "wordview.exe", "winword.exe", "excel.exe", "powerpnt.exe",
        "outlook.exe", "mspub.exe", "acrord32.exe", "acrord64.exe",
    ]

    filter_apinames = [
        "NtCreateFile",
    ]

    def on_call(self, call, process):
        pname = process["process_name"].lower()
        if pname in self.proc_list:
            filepath = call["arguments"]["filepath"]
            if filepath.endswith(".ocx") and "\\Macromed\\Flash\\" in filepath and call["arguments"]["create_disposition"] == 1:
                if pname not in self.pname:
                    self.pname.append(pname)
                self.mark_call()

    def on_complete(self):
        if len(self.pname) == 1:
            for pname in self.pname:
                self.description = "The process %s loaded Flash indicative of a possible exploit attempt" % pname
        elif len(self.pname) > 1:
            self.description = "The processes %s loaded Flash indicative of a possible exploit attempt" % ", ".join(self.pname)
        return self.has_marks()
