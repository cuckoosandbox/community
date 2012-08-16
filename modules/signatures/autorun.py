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
    name = "autorun"
    description = "Installs itself for autorun at Windows startup"
    severity = 3
    categories = ["generic"]
    authors = ["Michael Boman"]
    minimum = "0.4.1"

    def run(self, results):
        keys = [
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServices",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServicesOnce",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Active Setup\\\\Installed Components\\\\",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\"
        ]

        files = [
            ".*\\\\win.ini",
            ".*\\\\system.ini",
            ".*\\\\Start Menu\\\\Programs\\\\Startup"
        ]

        for key in results["behavior"]["summary"]["keys"]:
            for indicator in keys:
                regexp = re.compile(indicator, re.IGNORECASE)
                if regexp.match(key):
                    self.data.append({"key" : key})
                    return True

        for file_name in results["behavior"]["summary"]["files"]:
            for indicator in files:
                regexp = re.compile(indicator, re.IGNORECASE)
                if regexp.match(file_name):
                    self.data.append({"file" : file_name})
                    return True

        return False
