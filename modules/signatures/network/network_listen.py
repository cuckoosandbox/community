# Copyright (C) 2013 Claudio "nex" Guarnieri (@botherder), Accuvant, Inc. (bspengler@accuvant.com)
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

class NetworkListen(Signature):
    name = "network_listen"
    description = "Starts listening on a network socket"
    severity = 2
    categories = ["network"]
    authors = ["snemes", "nex", "Accuvant"]
    minimum = "2.0"

    filter_apinames = {"bind", "listen"}

    def init(self):
        self.binds = {}

    def on_call(self, call, process):
        socket = call["arguments"].get("socket")
        if not socket: return
        if call["api"] == "bind":
            self.binds[socket] = {
                "pid": self.pid,
                "cid": self.cid,
                "call": self.call
            }
        elif call["api"] == "listen":
            bind = self.binds.get(socket)
            if not bind: return
            self.mark(type="call", **bind)

    def on_complete(self):
        return self.has_marks()
