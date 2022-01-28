# Copyright (C) 2022, Updated 2022 for Cuckoo 2.0
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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class NetworkIPEXE(Signature):
    name = "network_ip_exe"
    description = "Executable is attempted to be downloaded from an IP"
    severity = 5
    categories = ["network", "downloader"]
    minimum = "2.0"

    def on_complete(self):
        ip = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\.exe")
        for http in self.get_results("network", {}).get("http", []):
            # Downloading an EXE from an IP is ALWAYS SKETCHY
            if re.search(ip, http["uri"]):
                self.mark_ioc("request", http["uri"])

        return self.has_marks()
