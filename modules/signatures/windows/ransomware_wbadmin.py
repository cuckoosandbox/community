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

import re

from lib.cuckoo.common.abstracts import Signature

class RansomwareWbadmin(Signature):
    name = "ransomware_wbadmin"
    description = "Uses wbadmin utility to delete backups or configuraton to prevent recovery of the system"
    severity = 3
    categories = ["ransomware"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    cmdline_re = (
        "wbadmin.*delete.*",
    )

    def on_complete(self):
        for cmdline in self.get_command_lines():
            for regex in self.cmdline_re:
                if re.match(regex, cmdline, re.I):
                    self.mark_ioc("cmdline", cmdline)
                    break

        return self.has_marks()
