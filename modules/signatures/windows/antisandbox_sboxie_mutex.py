# Copyright (C) 2015 KillerInstinct, Updated 2016 for Cuckoo 2.0
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

class AntisandboxSboxieMutex(Signature):
    name = "antisandbox_sboxie_mutex"
    description = "Detects Sandboxie using a known mutex"
    severity = 3
    categories = ["antisandbox"]
    authors = ["KillerInstinct"]
    minimum = "2.0"

    indicators = [
        "Sandboxie_SingleInstanceMutex_Control",
    ]

    def on_complete(self):
        for indicator in self.indicators:
            mutex = self.check_mutex(pattern=indicator, regex=True)
            if mutex:
                self.mark_ioc("mutex", mutex)

        return self.has_marks()
