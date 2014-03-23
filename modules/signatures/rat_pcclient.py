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

class PcClientMutexes(Signature):
    name = "rat_pcclient"
    description = "Creates known PcClient mutex and/or file changes."
    severity = 3
    categories = ["rat"]
    families = ["pcclient"]
    authors = ["threatlead"]
    minimum = "0.5"
    
    def run(self):
		## Mutex
        indicators = [
            ".*BKLANG.*",			## https://malwr.com/analysis/MDIxN2NhMjg4MTg2NDY4MWIyNTE0Zjk5MTY1OGU4YzE/
			".*VSLANG.*",
        ]
        
        for indicator in indicators:
            if self.check_mutex(pattern=indicator, regex=True):
                return True

		## Files
		indicators = [
            ".*\\\\syslog.dat",		# https://malwr.com/analysis/MDIxN2NhMjg4MTg2NDY4MWIyNTE0Zjk5MTY1OGU4YzE/
            ".*\\\\.*_lang.ini",	# https://malwr.com/analysis/MDIxN2NhMjg4MTg2NDY4MWIyNTE0Zjk5MTY1OGU4YzE/
            ".*\\\\[0-9]+_lang.dll",# https://malwr.com/analysis/MDIxN2NhMjg4MTg2NDY4MWIyNTE0Zjk5MTY1OGU4YzE/
            ".*\\\\[0-9]+_res.tmp", # https://malwr.com/analysis/MDIxN2NhMjg4MTg2NDY4MWIyNTE0Zjk5MTY1OGU4YzE/
        ]

        for indicator in indicators:
            if self.check_file(pattern=indicator, regex=True):
                return True

        return False
