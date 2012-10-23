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

import re

from lib.cuckoo.common.abstracts import Signature

class Autorun(Signature):
    name = "persistence_autorun"
    description = "Installs itself for autorun at Windows startup"
    severity = 3
    categories = ["persistence"]
    authors = ["Michael Boman"]
    minimum = "0.4.1"

    def run(self, results):
        indicators = [
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServices",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServicesOnce",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Active Setup\\\\Installed Components\\\\",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\"
        ]

        regexps = [re.compile(indicator) for indicator in indicators]

        for key in results["behavior"]["summary"]["keys"]:
            for regexp in regexps:
                if regexp.match(key):
                    self.data.append({"key" : key})
                    return True

        indicators = [
            ".*\\\\win.ini",
            ".*\\\\system.ini",
            ".*\\\\Start Menu\\\\Programs\\\\Startup"
        ]

        regexps = [re.compile(indicator) for indicator in indicators]

        for file_name in results["behavior"]["summary"]["files"]:
            for regexp in regexps:
                if regexp.match(file_name):
                    self.data.append({"file_name" : file_name})
                    return True

        return False
