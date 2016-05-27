# Copyright (C) 2016 Kevin Ross
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

class InfostealerRamScraping(Signature):
    name = "infostealer_ram_scraping"
    description = "Repeatedly reads process memory indicative of potential RAM scraping"
    severity = 2
    categories = ["infostealer", "pos"]
    minimum = "2.0"

    def on_complete(self):
        apistats = self.get_results("behavior", {}).get("apistats", {})
        for funcs in apistats.values():
            if funcs.get("ReadProcessMemory", 0) > 100:
                count = funcs.get("ReadProcessMemory", 0)
                self.mark_ioc("Number of ReadProcessMemory API calls", count)
                if count > 1500:
                    self.severity = 5
                elif count > 1000:
                    self.severity = 4
                elif count > 500:
                    self.severity = 3
                
                return True
