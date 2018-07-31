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

class CmdlineCompsecEvasion(Signature):
    name = "cmdline_comspec_evasion"
    description = "Uses the %COMSPEC% environment variable to access the command line interpreter to evade detection"
    severity = 3
    categories = ["commands"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    references = ["www.fireeye.com/content/dam/fireeye-www/blog/pdfs/dosfuscation-report.pdf"]

    def on_complete(self):
        for cmdline in self.get_command_lines():
            if "%comspec" in cmdline.lower():
                self.mark_ioc("cmdline", cmdline)

        return self.has_marks()

class CmdlineChracterObfsucation(Signature):
    name = "cmdline_chracter_obfuscation"
    description = "Appears to use character obfuscation in a command line"
    severity = 3
    categories = ["commands"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    references = ["www.fireeye.com/content/dam/fireeye-www/blog/pdfs/dosfuscation-report.pdf"]

    def on_complete(self):
        for cmdline in self.get_command_lines():
            if "cmd" in cmdline.lower() and (cmdline.count("^") > 3 or cmdline.count("&") > 6 or cmdline.count("+") > 4 or cmdline.count("\"") > 8):
                self.mark_ioc("cmdline", cmdline)

        return self.has_marks()
        
class CmdlineConcatenationObfsucation(Signature):
    name = "cmdline_concatenation_obfuscation"
    description = "Appears to use adjacent environment variables for concatenation reassembly obfuscation in a command line"
    severity = 3
    categories = ["commands"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    references = ["www.fireeye.com/content/dam/fireeye-www/blog/pdfs/dosfuscation-report.pdf"]

    def on_complete(self):
        for cmdline in self.get_command_lines():
            if "cmd" in cmdline.lower() and re.search('(%[^%]+%){4}', cmdline):
                self.mark_ioc("cmdline", cmdline)

        return self.has_marks()

class CmdlineSetObfsucation(Signature):
    name = "cmdline_set_obfuscation"
    description = "Appears to use set to define variables in command line likely for obfsucation"
    severity = 3
    categories = ["commands"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    references = ["www.fireeye.com/content/dam/fireeye-www/blog/pdfs/dosfuscation-report.pdf"]

    def on_complete(self):
        for cmdline in self.get_command_lines():
            if "cmd" in cmdline.lower() and cmdline.lower().count("set ") > 2:
                self.mark_ioc("cmdline", cmdline)

        return self.has_marks()
