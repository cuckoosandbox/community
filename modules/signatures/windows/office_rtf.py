# Copyright (C) 2018 Kevin Ross
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

class RTFUnknownVersion(Signature):
    name = "rtf_unknown_version"
    description = "RTF file has an unknown version"
    severity = 2
    categories = ["office"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    def on_complete(self):
        target = self.get_results("target", {})
        filetype = target.get("file", {}).get("type") or ""
        name = target.get("file", {}).get("name")
        if "Rich Text Format data" in filetype and "unknown version" in filetype:
            self.mark(
                filename=name,
                filetype_details=filetype,
            )
            for dropped in self.get_results("dropped", []):
                if "filepath" in dropped:
                    droppedtype = dropped["type"]
                    droppedname = dropped["name"]
                    if "Rich Text Format data" in droppedtype and "unknown version" in droppedtype:
                        self.mark(
                            dropped_filename=droppedname,
                            dropped_filetype_details=filetype,
                        )

        return self.has_marks()

class RTFCharacterSet(Signature):
    name = "rtf_unknown_character_set"
    description = "RTF file has an unknown character set"
    severity = 2
    categories = ["office"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    def on_complete(self):
        target = self.get_results("target", {})
        filetype = target.get("file", {}).get("type") or ""
        name = target.get("file", {}).get("name")
        if "Rich Text Format data" in filetype and "unknown character set" in filetype:
            self.mark(
                filename=name,
                filetype_details=filetype,
            )
            for dropped in self.get_results("dropped", []):
                if "filepath" in dropped:
                    droppedtype = dropped["type"]
                    droppedname = dropped["name"]
                    if "Rich Text Format data" in droppedtype and "unknown character set" in droppedtype:
                        self.mark(
                            dropped_filename=droppedname,
                            dropped_filetype_details=filetype,
                        )

        return self.has_marks()
