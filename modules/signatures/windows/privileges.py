# Copyright (C) 2017 Kevin Ross
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

class PrivilegeLUIDCheck(Signature):
    name = "privilege_luid_check"
    description = "Checks for the Locally Unique Identifier on the system for a suspicious privilege"
    severity = 2
    categories = ["privileges"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_apinames = [
        "LookupPrivilegeValueA",
        "LookupPrivilegeValueW",
    ]

    suspicious_privs = [
        "SeAssignPrimaryTokenPrivilege",
        "SeBackupPrivilege",
        "SeCreateGlobalPrivilege",
        "SeCreateTokenPrivilege",
        "SeDebugPrivilege",
        "SeEnableDelegationPrivilege",
        "SeMachineAccountPrivilege",
        "SeManageVolumePrivilege",
        "SeLoadDriverPrivilege",
        "SeRemoteShutdownPrivilege",
        "SeRestorePrivilege",
        "SeSecurityPrivilege",
        "SeShutdownPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeTcbPrivilege",
        "SeTrustedCredManAccessPrivilege",
    ]

    def on_call(self, call, process):
        privname = call["arguments"]["privilege_name"]
        for priv in self.suspicious_privs:
            if privname == priv:
                self.mark_call()

    def on_complete(self):
        return self.has_marks()
