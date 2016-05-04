# Copyright (C) 2015 KillerInstinct, Accuvant, Inc. (bspengler@accuvant.com)
# Copyright (C) 2016 Cuckoo Foundation
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
    description = "Creates known ransomware decryption instruction / key file."
    severity = 3
    categories = ["ransomware"]
    authors = ["KillerInstinct", "Cuckoo Technologies"]
    minimum = "2.0"

    indicators = [
        ".*\\\\help_decrypt\\.html$",
        ".*\\\\decrypt_instruction\.(html|txt)$",
        ".*\\\\help_your_files\.png$",
        ".*\\\\vault\.(key|txt)$",
        ".*\\\\!Decrypt-All-Files.*\.(txt|bmp)$",
        ".*\\\\help_restore_files\.txt$",
        ".*\\\\help_to_save_files\.(txt|bmp)$",
        ".*\\\\recovery_(file|key)\.txt$",
        ".*\\\\restore_files_.*\.(txt|html)$",
        ".*\\\\howto_restore_files.*\.(txt|html)$",
        ".*\\\\+-xxx-HELP-xxx-+.*\.(png|txt|html)$",
        ".*\\\\HELP_RECOVER_instructions\+.*\.(txt|html)$",
        ".*\\\\YOUR_FILES_ARE_ENCRYPTED\.HTML$",
        ".*\\\\_?how_recover.*\.(txt|html)$",
        ".*\\\\cl_data.*\.bak$",
        ".*\\\\READ\ ME\ FOR\ DECRYPT\.txt$",
        ".*\\\\YOUR_FILES.url$",
        ".*\\\\_How\ to\ decrypt\ LeChiffre\ files\.html$",
        ".*\\\\cryptinfo\.txt$",
        ".*\\\\README_DECRYPT_HYDRA_ID_.*(\.txt|\.jpg)$",
        ".*\\\\_Locky_recover_instructions\.txt$",
        ".*\\\\_DECRYPT_INFO_[a-z]{4,7}\.html$",
        ".*\\\\de_crypt_readme\.(html|txt|bmp)$",
        ".*\\\\HELP_YOUR_FILES\.(html|txt)$",
        ".*\\\\READ_IT\.txt$",
    ]

    def on_complete(self):
        for indicator in self.indicators:
            for filepath in self.check_file(pattern=indicator, regex=True, all=True):
                self.mark_ioc("file", filepath)

        return self.has_marks()
