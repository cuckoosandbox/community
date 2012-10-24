# Copyright (C) 2012 Claudio "nex" Guarnieri (@botherder)
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

class FTPStealer(Signature):
    name = "infostealer_ftp"
    description = "Harvests credentials from local FTP client softwares"
    severity = 3
    categories = ["infostealer"]
    authors = ["nex"]
    minimum = "0.4.1"

    def run(self, results):
        indicators = [
            "CuteFTP\\sm.dat",
            "FlashFXP\\3\\Sites.dat",
            "FlashFXP\\4\\Sites.dat",
            "FileZilla\\sitemanager.xml",
            "FileZilla\\recentservers.xml",
            "VanDyke\\Config\\Sessions",
            "FTP Explorer"
            "SmartFTP",
            "TurboFTP",
            "FTPRush",
            "LeapFTP",
            "FTPGetter",
            "ALFTP"
        ]

        for file_name in results["behavior"]["summary"]["files"]:
            for indicator in indicators:
                if indicator in file_name:
                    self.data.append({"file_name" : file_name})
                    return True

        return False
