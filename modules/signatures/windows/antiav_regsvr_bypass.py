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

class AntiAVSquiblydooBypass(Signature):
    name = "antiav_squiblydoo_bypass"
    description = "Squiblydoo application whitelist bypass attempt"
    severity = 3
    categories = ["bypass"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    def on_complete(self):
        for cmdline in self.get_command_lines():
            if "regsvr32" in cmdline.lower() and "scrobj.dll" in cmdline.lower():
                self.mark_ioc("cmdline", cmdline)

        return self.has_marks()

class AntiAVRegsvrScriptLaunch(Signature):
    name = "antiav_regsrv_script_launch"
    description = "Regsrv32 launching script module"
    severity = 3
    categories = ["bypass"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    def on_complete(self):
        for cmdline in self.get_command_lines():
            if "regsvr32" in cmdline.lower() and ("jscript.dll" in cmdline.lower() or "vbscript.dll" in cmdline.lower()):
                self.mark_ioc("cmdline", cmdline)

        return self.has_marks()

class AntiAVRegsvrHTTP(Signature):
    name = "antiav_regsrv_http"
    description = "Regsrv32 command line contains HTTP/HTTPS URL"
    severity = 3
    categories = ["bypass"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    def on_complete(self):
        for cmdline in self.get_command_lines():
            if "regsvr32" in cmdline.lower() and ("http\://" in cmdline.lower() or "https\://" in cmdline.lower()):
                self.mark_ioc("cmdline", cmdline)

        return self.has_marks()