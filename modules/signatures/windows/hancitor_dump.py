# Copyright (C) 2018 Fernando Dominguez
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

import re
from lib.cuckoo.common.abstracts import Signature

class HancitorDump(Signature):
    name = "hancitor_dump"
    description = "Hancitor dropper configuration dumped"
    severity = 5
    categories = ["cfgextr", "dropper"]
    authors = ["FDD"]
    minimum = "2.0"

    def on_complete(self):
        config = {}
        for procmem in self.get_results("procmemory", []):
            if "family" in config and "cnc" in config:
                continue

            for yara in procmem.get("yara", []):
                if "win_hancitor_" not in yara["name"]:
                    continue

                content = open(procmem["file"]).read()
                urls_re = re.compile("https?://[^\s/$.?#].[^\s|]*gate\.php", re.DOTALL)
                urls  = urls_re.findall(content)
                if urls:
                    config["cnc"] = urls

                config["family"] = "hancitor"
                self.marks.append({
                    "type": "config",
                    "config": config
                })

        return self.has_marks()
