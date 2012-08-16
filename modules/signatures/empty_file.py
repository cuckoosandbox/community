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

class EmptyFile(Signature):
    name = "empty_file"
    description = "Creates a empty file"
    severity = 2
    categories = ["generic"]
    authors = ["Michael Boman"]
    minimum = "0.4"

    def run(self, results):
        for dropped_file in results["dropped"]:
            if dropped_file["size"] == 0:
                self.data.append({"dropped_file" : dropped_file})
                return True

        return False
