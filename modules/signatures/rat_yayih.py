# Copyright (C) 2014 @threatlead
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

class Yayih(Signature):
    name = "rat_yayih"
    description = "Detected Yahih Rat trojan, based on Registry value."
    severity = 3
    categories = ["apt"]
    families = ["yayih"]
    authors = ["threatlead"]
    minimum = "1.0"
    evented = True
    
    def on_call(self, call, process):
        if call["api"].startswith("RegSetValueEx"):
            if self.get_argument(call, "ValueName").endswith("MicrosoftInfo"):
				## https://malwr.com/analysis/ZDEyYzE3ZTMwNjkxNDk4Mzg3OTg2ZDAyMTczZWZmMDY/
				return True
