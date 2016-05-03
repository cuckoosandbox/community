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

    proc_list =["wordview.exe","winword.exe","excel.exe","powerpnt.exe","outlook.exe","acrord32.exe","acrord64.exe"]

    filter_apinames = set(["InternetCrackUrlW","InternetCrackUrlA","URLDownloadToFileW","HttpOpenRequestW","InternetReadFile","WSASend"])
    filter_analysistypes = set(["file"])

    def on_call(self, call, process):
        pname = process["process_name"].lower()
        if pname in self.proc_list:
            self.mark_call()

    def on_complete(self):
        return self.has_marks()
