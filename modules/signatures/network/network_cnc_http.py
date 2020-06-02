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

class NetworkHTTPPOST(Signature):
    name = "network_http_post"
    description = "Sends data using the HTTP POST Method"
    severity = 2
    categories = ["http", "cnc"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_analysistypes = set(["file"])

    def on_complete(self):

        safelist = [
            "microsoft.com",
            "windowsupdate\.com",
            "adobe.com",
            ]

        for http in getattr(self, "get_net_http_ex", lambda: [])():
            is_safelisted = False
            for safelisted in safelist:
                if safelisted in http["host"]:
                    is_safelisted = True

            if not is_safelisted and http["method"] == "POST":
                request = "%s %s://%s%s" % (http["method"], http["protocol"], http["host"], http["uri"])
                self.mark_ioc("request", request)

        return self.has_marks()

class NetworkCnCHTTP(Signature):
    name = "network_cnc_http"
    description = "HTTP traffic contains suspicious features which may be indicative of malware related traffic"
    severity = 2
    categories = ["http", "cnc"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_analysistypes = set(["file"])

    def on_complete(self):

        safelist = [
            "microsoft.com",
            "windowsupdate\.com",
            "adobe.com",
            ]

        suspectrequests = []

        for http in getattr(self, "get_net_http_ex", lambda: [])():
            is_safelisted = False
            for safelisted in safelist:
                if safelisted in http["host"]:
                    is_safelisted = True

            # Check HTTP features
            reasons = []
            ip = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
            if not is_safelisted and http["method"] == "POST" and "Referer:" not in http["request"]:
                reasons.append("POST method with no referer header")

            if not is_safelisted and http["method"] == "POST" and "User-Agent:" not in http["request"]:
                reasons.append("POST method with no useragent header")

            if not is_safelisted and http["method"] == "GET" and "User-Agent:" not in http["request"]:
                reasons.append("GET method with no useragent header")

            if not is_safelisted and "HTTP/1.0" in http["request"]:
                reasons.append("HTTP version 1.0 used")

            if not is_safelisted and ip.match(http["host"]):
                reasons.append("Connection to IP address")

            if len(reasons) > 0:
                request = "%s %s://%s%s" % (http["method"], http["protocol"], http["host"], http["uri"])
                if request not in suspectrequests:
                    features = ', '.join(reasons)
                    suspectrequests.append(request)
                    self.mark(
                        suspicious_features=features,
                        suspicious_request=request,
                    )

        return self.has_marks()
