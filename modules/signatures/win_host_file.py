# Copyright (C) 2012 @threatlead
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

class HostFile(Signature):
    name = "win_host_file"
    description = "Read/Write Windows Host File"
    severity = 3
    categories = ["general"]
    families = ["windows"]
    authors = ["threatlead"]
    minimum = "0.5"

    def run(self):
        indicators = [
            ".*\\\\systEm32\\\\drivErs\\\\Etc\\\\hosts", # https://malwr.com/analysis/MGVmNzc0YTNiYTU0NGJjMDhmZjVhYjVlMTZiYjVmMTU/
        ]
        
        for indicator in indicators:
            if self.check_file(pattern=indicator, regex=True):
                return True

        return False
