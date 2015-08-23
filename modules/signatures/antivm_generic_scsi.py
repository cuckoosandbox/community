# Copyright (C) 2012 Claudio "nex" Guarnieri (@botherder)
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

class AntiVMSCSI(Signature):
    name = "antivm_generic_scsi"
    description = "Detects virtualization software with SCSI Disk Identifier trick"
    severity = 3
    categories = ["anti-vm"]
    authors = ["nex"]
    minimum = "2.0"

    indicator = \
        "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\" \
        "Target Id 0\\Logical Unit Id 0\\Identifier"

    def on_complete(self):
        if self.check_key(pattern=self.indicator):
            self.match(None, "registry", regkey=self.indicator)
