# Copyright (C) 2017 Kevin Ross
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

class ModifiesProxyWPAD(Signature):
    name = "modifies_proxy_wpad"
    description = "Sets or modifies WPAD proxy autoconfiguration file for traffic interception"
    severity = 3
    categories = ["infostealer"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    evented = True

    filter_apinames = [
        "RegSetValueExA",
        "RegSetValueExW",
        "NtSetValueKey",
    ]

    def on_call(self, call, process):
        if process["process_name"] not in ["chrome.exe", "iexplore.exe", "firefox.exe"]:
            key = call["arguments"]["regkey"]
            if key and "\\software\\microsoft\\windows\\currentversion\\internet settings\\wpad\\" in key.lower():
                self.mark_call()

    def on_complete(self):
        return self.has_marks()

class ModifiesProxyOverride(Signature):
    name = "modifies_proxy_override"
    description = "Modifies proxy override settings possibly for traffic interception"
    severity = 3
    categories = ["infostealer"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    evented = True

    filter_apinames = [
        "RegSetValueExA",
        "RegSetValueExW",
        "NtSetValueKey",
    ]

    def on_call(self, call, process):
        if process["process_name"] not in ["chrome.exe", "iexplore.exe", "firefox.exe"]:
            key = call["arguments"]["regkey"].lower()
            if key and "\\software\\microsoft\\windows\\currentversion\\internet settings\\proxyoverride" in key:
                self.mark_call()

    def on_complete(self):
        return self.has_marks()

class ModifiesProxyAutoConfig(Signature):
    name = "modifies_proxy_autoconfig"
    description = "Modifies proxy autoconfiguration settings possibly for traffic interception"
    severity = 3
    categories = ["infostealer"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    evented = True

    filter_apinames = [
        "RegSetValueExA",
        "RegSetValueExW",
        "NtSetValueKey",
    ]

    def on_call(self, call, process):
        if process["process_name"] not in ["chrome.exe", "iexplore.exe", "firefox.exe"]:
            key = call["arguments"]["regkey"].lower()
            if key and "\\software\\microsoft\\windows\\currentversion\\internet settings\\autoconfigurl" in key:
                self.mark_call()

    def on_complete(self):
        return self.has_marks()

class DisablesProxy(Signature):
    name = "disables_proxy"
    description = "Disables proxy possibly for traffic interception"
    severity = 3
    categories = ["infostealer"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    evented = True

    filter_apinames = [
        "RegSetValueExA",
        "RegSetValueExW",
        "NtSetValueKey",
    ]

    def on_call(self, call, process):
        if process["process_name"] not in ["chrome.exe", "iexplore.exe", "firefox.exe"]:
            key = call["arguments"]["regkey"].lower()
            if key and "\\software\\microsoft\\windows\\currentversion\\internet settings\\proxyenable" in key and call["arguments"]["value"] == 0:
                self.mark_call()

    def on_complete(self):
        return self.has_marks()
