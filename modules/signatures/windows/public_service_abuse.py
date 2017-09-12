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

class PUB_SERV_ABUSE(Signature):
    name = "public_service_abuse"
    description = "Abusing legit services for malware distribution"
    severity = 2
    categories = ["http"]
    authors = ["doomedraven"]
    minimum = "2.0"

    patterns = [
        ".*my.sharepoint.com.*",
        "https://www.evernote.com/shard/.+/sh/.+/res/.*",
        "https://docs.google.com/uc\?authuser=\d{1}&id=[\w\d]+&export=download"
    ]

    def on_complete(self):
        urls = set()
        for http in self.get_net_http_ex():
            urls.add("%s://%s%s" % (
                    http["protocol"], http["host"], http["uri"]
                )
            )

        for pattern in self.patterns:
            url = self._check_value(pattern=pattern,
                                     subject=list(urls),
                                     regex=True,
                                     all=False)
            if url:
                self.mark_ioc("url", url)

        return self.has_marks()
