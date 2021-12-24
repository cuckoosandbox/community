# Copyright (C) 2012-2014 Claudio "nex" Guarnieri (@botherder)
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
import re

class Log4Shell(Signature):
    name = "Log4Shell"
    description = "Log4Shell"
    severity = 3
    authors = ["Busra Yenidogan"]
    minimum = "2.0"

    user_agent = "(?i)((%(25){0,}20|\s)*(%(25){0,}24|\$)(%(25){0,}20|\s)*(%(25){0,}7B|{){0,1}(%(25){0,}20|\s)*(%(25){0,}(6A|4A)|J)(%(25){0,}(6E|4E)|N)(%(25){0,}(64|44)|D)(%(25){0,}(69|49)|I)(%(25){0,}20|\s)*(%(25){0,}3A|:)[\w\%]+(%(25){1,}3A|:)(%(25){1,}2F|\/)|\$((::-[A-Z%]}\$){1,}|(ENV|LOWER|UPPER):).+[:}]{2}\/)[^\n]+"

    def on_complete(self):
        for http in self.get_net_http():
            if re.search(self.user_agent, http.get("user-agent","")):
                self.mark_ioc("http", http)
        return self.has_marks()
