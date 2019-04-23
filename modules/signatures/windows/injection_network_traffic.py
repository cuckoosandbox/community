# Copyright (C) 2016 Kevin Ross
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

class InjectionNetworkTraffic(Signature):
    name = "injection_network_trafic"
    description = "A system process is connecting to the network likely as a result of process injection"
    severity = 3
    categories = ["injection", "cnc", "stealth"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    ttp = ["T1071"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.pname = []

    proc_list = [
        "conhost.exe",
        "csrss.exe",
        "dwm.exe",
        "explorer.exe",
        "lsass.exe",
        "services.exe",
        "smss.exe",
        "userinit.exe",
        "wininit.exe",
        "winlogon.exe",
    ]

    filter_apinames = [
        "InternetConnectA", "InternetConnectW", "InternetCrackUrlA", "InternetCrackUrlW", "InternetCrackUrlA", "InternetCrackUrlW",
        "URLDownloadToFileA","URLDownloadToFileW", "URLDownloadToCacheFileA", "URLDownloadToCacheFileW", "HttpOpenRequestA",
        "HttpOpenRequestW", "WSASend", "send", "sendto", "connect",
    ]

    def on_call(self, call, process):
        pname = process["process_name"].lower()
        host = ""
        if pname in self.proc_list:
            if "ip_address" in call["arguments"]:
                host = call["arguments"]["ip_address"]
            elif "hostname" in call["arguments"]:
                host = call["arguments"]["hostname"]

            if host != "":
                if not host.startswith(("127.", "10.", "172.16.", "192.168.")):
                    if pname not in self.pname:
                        self.pname.append(pname)
                    self.mark_call()
            else:
                if pname not in self.pname:
                    self.pname.append(pname)
                self.mark_call()

    def on_complete(self):
        if len(self.pname) == 1:
            self.description = "Network communications indicative of possible code injection originated from the process "
            for pname in self.pname:
                self.description += pname
        elif len(self.pname) > 1:
            self.description = "Network communications indicative of possible code injection originated from the processes "
            self.description += ", ".join(self.pname)
        return self.has_marks()
