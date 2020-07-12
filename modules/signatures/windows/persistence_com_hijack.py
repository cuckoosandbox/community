# Copyright (C) 2017 Cuckoo Sandbox
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

class PersistenceComHijack(Signature):
    name = "persistance_com_hijack"
    description = "Defines a COM object for DLL injection (possibly to achieve persistence)"
    severity = 3
    categories = ["persistance", "com"]
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"
    evented = True

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW", "NtSetValueKey"])

    known_objects = {
        "{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}": "CAccPropServicesClass",
        "{BCDE0395-E52F-467C-8E3D-C4579291692E}": "MMDeviceEnumerator",
    }

    def on_call(self, call, process):
        if not "regkey" in call["arguments"] or not "value" in call["arguments"]:
            return

        regkey = call["arguments"]["regkey"]
        regvalue = call["arguments"]["value"]
        if not isinstance(regvalue, basestring):
            return

        if "\CLSID\\" in regkey:
            self.mark_call()
            for obj, klass in self.known_objects.iteritems():
                if obj in regkey:
                    self.severity = 5
                    self.mark_ioc("Hijacked well-kwown class", klass)

    def on_complete(self):
        return self.has_marks()
