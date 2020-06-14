# Copyright (C) 2012,2014,2015 Michael Boman (@mboman), Optiv, Inc. (brad.spengler@optiv.com)
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

# Additional keys added from SysInternals Administrators Guide

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class COMHijacking(Signature):
    name = "COM_Hijacking"
    description = "Hijacking a COM object for persistence."
    severity = 3
    categories = ["persistence"]
    authors = ["kez"]
    minimum = "2.0"
    ttp = ["T1122"]

    regkeys_re = [                
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\clsid\\\\[^\\\\]*\\\\InprocServer32\\\\\(Default\)",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\clsid\\\\[^\\\\]*\\\\LocalServer32\\\\\(Default\)",
    ]

    filter_apinames = [
        "RegSetValueExA",
        "RegSetValueExW",
        "NtSetValueKey",
    ]

    def on_call(self, call, process):
        if call["status"]:
            regkey = call["arguments"]["regkey"]
            regvalue = call["arguments"]["value"]
            for indicator in self.regkeys_re:
                if re.match(indicator, regkey, re.IGNORECASE):
                    self.mark(
                        reg_key=regkey,
                        reg_value=regvalue,
                    )

    def on_complete(self):
        return self.has_marks()



