# Copyright (C) 2013 Claudio "nex" Guarnieri (@botherder)
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

class NetworkSMTP(Signature):
    name = "network_smtp"
    description = "Makes SMTP requests, possibly sending spam"
    severity = 3
    categories = ["smtp", "spam"]
    authors = ["nex", "RicoVZ"]
    minimum = "2.0.0"

    def on_complete(self):
        for s in getattr(self, "get_net_smtp_ex", lambda: [])():
            if s["req"]["username"] is None:
                self.mark(
                    server=s["dst"], sender=s["req"]["mail_from"],
                    receiver=s["req"]["mail_to"]
                )
            else:
                self.mark(
                    server=s["dst"], sender=s["req"]["mail_from"],
                    receiver=s["req"]["mail_to"], user=s["req"]["username"],
                    password=s["req"]["password"]
                )

        if not self.has_marks():
            return len(self.get_net_smtp()) > 0
        else:
            return True
