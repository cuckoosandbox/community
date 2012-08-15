# Copyright (C) 2012 Michael Boman (@mboman)
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

class UPXCompressed(Signature):
    name = "upx_compressed"
    description = "The executable is compressed using UPX"
    severity = 2
    categories = ["packers"]
    authors = ["Michael Boman"]
    minimum = "0.4"

    def run(self, results):
        for pe_section in results["static"]["pe_sections"]:
            if pe_section["name"].startswith("UPX"):
                self.data.append({"pe_section" : pe_section})
                return True

        return False
