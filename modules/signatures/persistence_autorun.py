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

# Based on information from http://antivirus.about.com/od/windowsbasics/tp/autostartkeys.htm

from lib.cuckoo.common.abstracts import Signature

class Autorun(Signature):
    name = "persistence_autorun"
    description = "Installs itself for autorun at Windows startup"
    severity = 3
    categories = ["persistence"]
    authors = ["Michael Boman", "nex"]
    minimum = "0.5"

    def run(self):
        indicators = [
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run$",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce$",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServices$",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServicesOnce$",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon$",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run$",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Active\\ Setup\\\\Installed Components\\\\.*"
        ]

        for indicator in indicators:
            if self.check_key(pattern=indicator, regex=True):
                return True

        indicators = [
            ".*\\\\win\.ini$",
            ".*\\\\system\.ini$",
            ".*\\\\Start Menu\\\\Programs\\\\Startup$"
        ]

        for indicator in indicators:
            if self.check_file(pattern=indicator, regex=True):
                return True

        return False
