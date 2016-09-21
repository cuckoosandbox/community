# Copyright (C) 2016 Kevin Ross, Uses code from KillerInstinct signature https://github.com/spender-sandbox/community-modified/blob/master/modules/signatures/ransomware_files.py
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

class RansomwareExtensions(Signature):
    name = "ransomware_extensions"
    description = "Appends known ransomware file extensions to files that have been encrypted"
    severity = 3
    categories = ["ransomware"]
    authors = ["Kevin Ross"]

    indicators = [
        (".*\.aaa$", ["TelsaCrypt"]),
        (".*\.aba$", ["TelsaCrypt"]),
        (".*\.ccc$", ["TelsaCrypt"]),
        (".*\.ecc$", ["TelsaCrypt"]),
        (".*\.exx$", ["TelsaCrypt"]),
        (".*\.ezz$", ["TelsaCrypt"]),
        (".*\.vvv$", ["TelsaCrypt"]),
        (".*\.rdm$", ["TelsaCrypt"]),
        (".*\.rrk$", ["TelsaCrypt"]),
        (".*\.toxcrypt$", ["ToxCrypt"]),
        (".*\.hydracrypt_ID_[a-z0-9]{8}$", ["HydraCrypt"]),
        (".*\.hydracrypttmp_ID_[a-z0-9]{8}$", ["HydraCrypt"]),
        (".*\.locky$", ["Locky"]),
        (".*\.wflx$", ["Locky"]),
        (".*\.locked$", ["Locked"]),
        (".*\.cerber[1-3]$", ["Cerber"]),
        (".*\.encrypt$", [""]),
        (".*\.R5A$", ["7ev3n"]),
        (".*\.R4A$", ["7ev3n"]),
        (".*\.herbst$", ["Herbst"]),
        (".*\.CrySiS$", ["Crysis"]),
        (".*\.bart\.zip$", ["Bart"]),
        (".*\.zepto$", ["Zepto"]),
        (".*\.crypt$", ["CryptXXX"]),
        (".*\.crypz$", ["CryptXXX"]),
        (".*\.cryp1$", ["CryptXXX"]),
        (".*\.[0-9A-F]{32}\.[0-9A-F]{5}$", ["CryptXXX"]),
        (".*\.id_[^\/]*\.scl$", ["CryptFile2"]),
        (".*\.razy$", ["Razy"]),
        (".*\.Venus(f|p)$", ["VenusLocker"]),
        (".*\.fs0ciety$", ["Fsociety"]),
        (".*\.cry$", ["CryLocker"]),
        (".*\.locked$", ["multi-family"]),
        (".*\.locklock$", ["LockLock"]),
        (".*\.fantom$", ["Fantom"]),
        (".*_nullbyte$", ["Nullbyte"]),
        (".*\.purge$", ["Globe"]),
        (".*\.domino$", ["Domino"]),
    ]

    def on_complete(self):
        for indicator in self.indicators:
            for filepath in self.check_file(pattern=indicator[0], regex=True, all=True):
                self.mark_ioc("file", filepath)
                if indicator[1]:
                    self.description = (
                        "Appends known %s ransomware file extensions to "
                        "files that have been encrypted." %
                        "/".join(indicator[1])
                    )

        return self.has_marks()
