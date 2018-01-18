# Copyright (C) 2018 Kevin Ross
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

class ClearsEventLogs(Signature):
    name = "clears_event_logs"
    description = "Uses Windows command to clear Windows event logs"
    severity = 3
    categories = ["commands", "stealth"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    utilities = [
        "wevtutil cl",
        "wevtutil.exe cl"
    ]

    def on_complete(self):
        for cmdline in self.get_command_lines():
            for utility in self.utilities:
                if utility in cmdline.lower():
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()

class ClearPermissionEventLogs(Signature):
    name = "clear_permission_event_logs"
    description = "Manipulates event log permissions likely to enable clearing of logs"
    severity = 3
    categories = ["commands", "stealth"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    utilities = [
        "wevtutil sl",
        "wevtutil.exe sl"
    ]

    def on_complete(self):
        for cmdline in self.get_command_lines():
            for utility in self.utilities:
                if utility in cmdline.lower() and "/ca:" in cmdline.lower():
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()
