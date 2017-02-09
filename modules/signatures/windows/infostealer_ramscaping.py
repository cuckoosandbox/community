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

class InfoStealerRamScraping(Signature):
    name = "infostealer_ramscraping"
    description = "Appears to be performing RAM scraping to retrieve information from the memory of another process"
    severity = 3
    categories = ["infostealer"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_apinames = set(["ReadProcessMemory"])

    def on_call(self, call, process):
        handle = call["arguments"]["process_handle"]
        if handle != "0xffffffff" and handle != "0x00000000":
            self.mark_call()

    def on_complete(self):
        return self.has_marks(50)
