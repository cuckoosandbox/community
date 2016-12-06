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
        (".*\.toxcrypt$", ["ToxCrypt"]),
        (".*\.hydracrypt_ID_[a-z0-9]{8}$", ["HydraCrypt"]),
        (".*\.hydracrypttmp_ID_[a-z0-9]{8}$", ["HydraCrypt"]),
        (".*\.locked$", ["Locked"]),
        (".*\.cerber$", ["Cerber"]),
        (".*\.cerber2$", ["Cerber"]),
        (".*\.cerber3$", ["Cerber"]),
        (".*\.encrypt$", [""]),
        (".*\.R5A$", ["7ev3n"]),
        (".*\.R4A$", ["7ev3n"]),
        (".*\.herbst$", ["Herbst"]),
        (".*\.CrySiS$", ["Crysis"]),
        (".*\.bart\.zip$", ["Bart"]),
        (".*\.crypt$", ["CryptXXX"]),
        (".*\.crypz$", ["CryptXXX"]),
        (".*\.cryp1$", ["CryptXXX"]),
        (".*\.[0-9A-F]{32}\.[0-9A-F]{5}$", ["CryptXXX"]),
        (".*\.id_[^\/]*\.scl$", ["CryptFile2"]),
        (".*\.id_[^\/]*\.rscl$", ["CryptFile2"]),
        (".*\.razy$", ["Razy"]),
        (".*\.Venus(f|p)$", ["VenusLocker"]),
        (".*\.fs0ciety$", ["Fsociety"]),
        (".*\.cry$", ["CryLocker"]),
        (".*\.locklock$", ["LockLock"]),
        (".*\.fantom$", ["Fantom"]),
        (".*_nullbyte$", ["Nullbyte"]),
        (".*\.purge$", ["Globe"]),
        (".*\.globe$", ["Globe"]),
        (".*\.raid10$", ["Globe"]),
        (".*\.domino$", ["Domino"]),
        (".*\.wflx$", ["WildFire-Locker"]),
        (".*\.locky$", ["Locky"]),
        (".*\.zepto$", ["Locky"]),
        (".*\.odin$", ["Locky"]),
        (".*\.shit$", ["Locky"]),
        (".*\.thor$", ["Locky"]),
        (".*\.aesir$", ["Locky"]),
        (".*\.zzzzz$", ["Locky"]),
        (".*\.osiris$", ["Locky"]),
        (".*\.locked$", ["multi-family"]),
        (".*\.encrypted$", ["multi-family"]),
        (".*dxxd$", ["DXXD"]),
        (".*\.~HL[A-Z0-9]{5}$", ["HadesLocker"]),
        (".*\.exotic$", ["Exotic"]),
        (".*\.k0stya$", ["Kostya"]),
        (".*\.1txt$", ["Enigma"]),
        (".*\.0x5bm$", ["Nuke"]),
        (".*\.nuclear55$", ["Nuke"]),
        (".*\.comrade$", ["Comrade-Circle"]),
        (".*\.rip$", ["KillerLocker"]),
        (".*\.adk$", ["AngryDuck"]),
        (".*\.lock93$", ["Lock93"]),
        (".*\.Alcatraz$", ["Alcatraz-Locker"]),
        (".*\.dCrypt$", ["DummyLocker"]),
        (".*\.enc$", ["encryptJJS"]),
        (".*\.rnsmwr$", ["Gremit"]),
        (".*\.da_vinci_code$", ["Troldesh"]),
        (".*\.magic_software_syndicate$", ["Troldesh"]),
        (".*\.no_more_ransom$", ["Troldesh"]),
        (".*_luck$", ["CryptoLuck"]),
        (".*\.CHIP$", ["CHIP"]),
    ]

    def on_complete(self):
        for indicator in self.indicators:
            for filepath in self.check_file(pattern=indicator[0], regex=True, all=True):
                self.mark_ioc("file", filepath)
                if indicator[1]:
                    self.description = (
                        "Appends a known %s ransomware file extension to "
                        "files that have been encrypted" %
                        "/".join(indicator[1])
                    )

        return self.has_marks()
