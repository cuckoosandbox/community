# Copyright (C) 2015 KillerInstinct
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

class RansomwareFiles(Signature):
    name = "ransomware_files"
    description = "Created known ransomware decryption instruction / key file."
    severity = 3
    categories = ["ransomware"]
    authors = ["KillerInstinct"]
    minimum = "0.5"

    def run(self):
        # Lower-case file names
        file_list = [
            "help_decrypt.html",
            "decrypt_instruction.html",
            "decrypt_instructions.txt",
            "vault.key",
            "\\vault.txt",
        ]

        if "behavior" in self.results:
            if "summary" in self.results["behavior"]:
                if "files" in self.results["behavior"]["summary"]:
                    for path in self.results["behavior"]["summary"]["files"]:
                        for badfile in file_list:
                            if badfile in path.lower():
                                return True

        return False
