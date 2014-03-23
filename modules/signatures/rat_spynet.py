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

class SpynetRat(Signature):
    name = "rat_spynet"
    description = "Creates known SpyNet mutexes and/or registry changes."
    severity = 3
    categories = ["rat"]
    families = ["spynet"]
    authors = ["threatlead"]
    minimum = "0.5"

    def run(self):
    	## Mutex
        indicators = [
            ".*CYBERGATEUPDATE",	## https://malwr.com/analysis/ZDQ1NjBhNWIzNTdkNDRhNjhkZTFmZTBkYTU2YjMwNzg/
            ".*\(\(SpyNet\)\).*",	## https://malwr.com/analysis/MjkxYmE2YzczNzcwNGJiZjljNDcwMzA2ZDkyNDU2Y2M/
            ".*Spy-Net.*",			## https://malwr.com/analysis/N2E3NWRiNDMyYjIwNGE0NTk3Y2E5NWMzN2UwZTVjMzI/
            ".*X_PASSWORDLIST_X.*",	## https://malwr.com/analysis/N2Q2NWY0Y2MzOTM0NDEzNmE1MTdhOThiNTQxMzhiNzk/
            ".*X_BLOCKMOUSE_X.*",	## https://malwr.com/analysis/N2Q2NWY0Y2MzOTM0NDEzNmE1MTdhOThiNTQxMzhiNzk/
            ".*PERSIST",			## https://malwr.com/analysis/N2Q2NWY0Y2MzOTM0NDEzNmE1MTdhOThiNTQxMzhiNzk/
            ".*_SAIR",				## https://malwr.com/analysis/N2Q2NWY0Y2MzOTM0NDEzNmE1MTdhOThiNTQxMzhiNzk/
        ]

        for indicator in indicators:
            if self.check_mutex(pattern=indicator, regex=True):
                return True

        ## Registry
        regkeys = [
            ".*\\SpyNet\\.*",
        ]

        for regkey in regkeys:
            if self.check_key(pattern=regkey, regex=True):
                return True
		
		return False
