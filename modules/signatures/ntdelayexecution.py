# Copyright (C) 2012 Thomas Andersen
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

class NtDelayExecution(Signature):

    name = "ntdelayexecution"
    description = "Delays execution more than threshold (default 1 min)"
    severity = 2
    categories = ["generic"]
    authors = ["Thomas Andersen"]

    def run(self, results):
        threshold = 60000
        delaytime = 0
        for process in results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "NtDelayExecution":
                   delaytime+=int(call["arguments"][0]["value"])
                   if delaytime >= threshold:
                       return True

        return False

