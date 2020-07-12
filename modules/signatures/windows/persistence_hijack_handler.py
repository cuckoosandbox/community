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

class PersistenceHijackRegistry(Signature):
    name = "persistance_hijack_registry"
    description = "Changes the default open handler for a file extension"
    severity = 3
    categories = ["persistance", "registry"]
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"
    evented = True

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW", "NtSetValueKey"])

    def on_call(self, call, process):
        regkey = call["arguments"]["regkey"]
        regvalue = call["arguments"]["value"]
        if not isinstance(regvalue, basestring):
            return

        if "\shell\open\command\(Default)" in regkey:
            self.mark_call()

    def on_complete(self):
        return self.has_marks()
