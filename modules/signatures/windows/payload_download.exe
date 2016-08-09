# Copyright (C) 2016 Kevin Ross. Also uses code from Will Metcalf
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

class NetworkDocumentFile(Signature):
    name = "network_document_file"
    description = "A document file initiated network communications indicative of a potential exploit or payload download"
    severity = 3
    categories = ["exploit", "downloader"]
    authors = ["Kevin Ross", "Will Metcalf"]
    minimum = "2.0"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.pname = []
        self.proc_list =["wordview.exe","winword.exe","excel.exe","powerpnt.exe","outlook.exe","acrord32.exe","acrord64.exe","wscript.exe"]

    filter_apinames = set(["InternetCrackUrlW","InternetCrackUrlA","URLDownloadToFileW","HttpOpenRequestW","WSASend"])
    filter_analysistypes = set(["file"])

    def on_call(self, call, process):
        pname = process["process_name"].lower()
        if pname in self.proc_list:
            if pname not in self.pname:
                self.pname.append(pname)
            self.mark_call()

    def on_complete(self):
        if len(self.pname) == 1:
            self.description = "Network communications indicative of a potential document or script payload download was initiated by the process "
            for pname in self.pname:
                self.description += pname
        elif len(self.pname) > 1:
            self.description = "Network communications indicative of a potential document or script payload download was initiated by the processes "
            list = ", ".join(self.pname )
            self.description += list
        return self.has_marks()

from lib.cuckoo.common.abstracts import Signature

class NetworkEXE(Signature):
    name = "network_downloader_exe"
    description = "An executable file was downloaded"
    severity = 2
    categories = ["exploit", "downloader"]
    authors = ["Kevin Ross", "Will Metcalf"]
    minimum = "2.0"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.pname = []
        self.high_risk_proc = ["wordview.exe","winword.exe","excel.exe","powerpnt.exe","outlook.exe","acrord32.exe","acrord64.exe","wscript.exe","java.exe"]

    filter_apinames = set(["recv", "InternetReadFile"])
    filter_analysistypes = set(["file"])

    def on_call(self, call, process):
        buf = call["arguments"]["buffer"]
        pname = process["process_name"].lower()
        if "MZ" in buf and "This program" in buf:
            if pname in self.high_risk_proc:
                self.severity = 3
            if pname not in self.pname:
                self.pname.append(pname)
            self.mark_call()

    def on_complete(self):
        if len(self.pname) == 1:
            self.description = "An executable file was downloaded by the process  "
            for pname in self.pname:
                self.description += pname
        elif len(self.pname) > 1:
            self.description = "An executable file was downloaded by the processes "
            list = ", ".join(self.pname )
            self.description += list
        return self.has_marks()

class SuspiciousWriteEXE(Signature):
    name = "suspicious_write_exe"
    description = "Wrote an executable file to disk"
    severity = 3
    categories = ["exploit", "downloader", "virus"]
    authors = ["Will Metcalf"]
    minimum = "2.0"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.pname = []
        self.susp_proc_list =["wordview.exe","winword.exe","excel.exe","powerpnt.exe","outlook.exe","wscript.exe","java.exe"]

    filter_apinames = set(["NtWriteFile"])
    filter_analysistypes = set(["file"])

    def on_call(self, call, process):
        pname = process["process_name"].lower()
        if pname in self.susp_proc_list:
            buff = call["arguments"]["buffer"]
            if buff and len(buff) > 2 and buff.startswith("MZ") and "This program" in buff:
                if pname not in self.pname:
                    self.pname.append(pname)               
                self.mark_call()

    def on_complete(self):
        if len(self.pname) == 1:
            for pname in self.pname:
                self.description = "The process %s wrote an executable file to disk" % pname
        elif len(self.pname) > 1:
            list = ", ".join(self.pname )
            self.description = "The processes %s wrote an executable file to disk" % list
        return self.has_marks()
