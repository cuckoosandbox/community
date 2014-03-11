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

class PoisonIvyMutexes(Signature):
    name = "rat_poisonivy_mutexes"
    description = "Creates known Poison Ivy mutexes"
    severity = 3
    categories = ["rat"]
    families = ["poison ivy"]
    authors = ["threatlead"]
    minimum = "0.5"

    def run(self):
        indicators = [
            ".*\)\!VoqA\.I4",		## https://malwr.com/analysis/M2QwZTJkMjhjZjQ5NGYyYmIwZTlhZmNhNGMxNjkxYTM/
        ]

        for indicator in indicators:
            if self.check_mutex(pattern=indicator, regex=True):
                return True

        return False