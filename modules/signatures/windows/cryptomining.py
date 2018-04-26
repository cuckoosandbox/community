# Copyright (C) 2018 Kevin Ross

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

class CryptoMiningStratumCommand(Signature):
    name = "cryptomining_stratum_command"
    description = "A stratum cryptocurrency mining command was executed"
    severity = 3
    categories = ["mining", "cryptocurrency"]
    authors = ["Kevin Ross", "Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        xmr_address_re = '-u[ ]*4[0-9AB][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{93}'
        xmr_strings = ["stratum+tcp://", "xmrig", "xmr-stak", "supportxmr.com:", "dwarfpool.com:", "minergate"]

        for cmdline in self.get_command_lines():
            if re.search(xmr_address_re, cmdline):
                self.mark_ioc("cmdline", cmdline)
            for xmr_string in xmr_strings:
                if xmr_string in cmdline.lower():
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()
