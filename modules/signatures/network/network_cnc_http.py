# Copyright (C) 2015 Kevin Ross, Updated 2016 for Cuckoo 2.0
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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class NetworkCnCHTTP(Signature):
    name = "network_cnc_http"
    description = "HTTP traffic contains suspicious features which may be indicative of malware related traffic"
    severity = 2
    categories = ["http", "cnc"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_analysistypes = set(["file"])

    def on_complete(self):

        whitelist = [
            "^http://.*\.microsoft\.com/.*",
            "^http://.*\.windowsupdate\.com/.*",
            "http://.*\.adobe\.com/.*",
            ]

        # HTTP request Features. Done like this due to for loop appending data each time instead of once so we wait to end of checks to add summary of anomalies
        post_noreferer = 0
        post_nouseragent = 0
        get_nouseragent = 0
        version1 = 0
        iphost = 0

        # Scoring
        cnc_score = 0
        suspectrequest = []

        if self.get_net_http():
            for req in self.get_net_http():
                is_whitelisted = False
                for white in whitelist:
                    if re.match(white, req["uri"], re.IGNORECASE):
                        is_whitelisted = True                              

                # Check HTTP features
                request = req["uri"]
                ip = re.compile("^http\:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
                if not is_whitelisted and req["method"] == "POST" and "Referer:" not in req["data"]:
                    post_noreferer += 1
                    cnc_score += 1

                if not is_whitelisted and req["method"] == "POST" and "User-Agent:" not in req["data"]:
                    post_nouseragent += 1
                    cnc_score += 1

                if not is_whitelisted and req["method"] == "GET" and "User-Agent:" not in req["data"]:
                    get_nouseragent += 1
                    cnc_score += 1

                if not is_whitelisted and req["version"] == "1.0":
                    version1 += 1
                    cnc_score += 1

                if not is_whitelisted and ip.match(request):
                    iphost += 1
                    cnc_score += 1

                if not is_whitelisted and cnc_score > 0:
                    if suspectrequest.count(request) == 0:
                        suspectrequest.append(request)

        if post_noreferer > 0:
            self.mark_ioc("reason for suspicion", "HTTP traffic contains a POST request with no referer header")

        if post_nouseragent > 0:
            self.mark_ioc("reason for suspicion", "HTTP traffic contains a POST request with no user-agent header")

        if get_nouseragent > 0:
            self.mark_ioc("reason for suspicion", "HTTP traffic contains a GET request with no user-agent header")

        if version1 > 0:
            self.mark_ioc("reason for suspicion", "HTTP traffic uses version 1.0")

        if iphost > 0:
            self.mark_ioc("(reason for suspicion", "HTTP connection was made to an IP address rather than domain name")

        if len(suspectrequest) > 0:
            for request in suspectrequest:
                self.mark_ioc("suspicious request", request)

        return self.has_marks()
