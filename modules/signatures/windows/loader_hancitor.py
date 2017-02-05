# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import base64
import re

from lib.cuckoo.common.abstracts import Signature

class Hancitor(Signature):
    name = "loader_hancitor"
    description = "Creates known Hancitor loader URLs and/or C2 request"
    severity = 3
    categories = ["loader"]
    families = ["hancitor"]
    authors = ["ronbarrey"]
    minimum = "2.0"

    filter_apinames = "HttpSendRequestA", "InternetCrackUrlA", "InternetReadFile"

    url_re = ".*[\.com|ru]\/ls[0-9]\/.*\.php"
    post_re = "GUID\=\d+\&BUILD\=\w+\&INFO\=.*\&IP\=[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\&TYPE\=\d+\&WIN\=.*"
    c2_re = "^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})$"

    c2_xor_key = 122

    def on_call(self, call, process):
        post = call["arguments"].get("post_data", {})
        url = call["arguments"].get("url", {})
        buffer = call["arguments"].get("buffer", {})

        if post:
            if re.match(self.post_re, post):
                self.mark_ioc("post_data", post, process["process_name"])

        if buffer:
            match = re.match(self.c2_re, buffer, re.I)
            if match:
                decoded = base64.b64decode(buffer)
                decrypted = ""
                for ch in decoded:
                    decrypted += chr(ord(ch) ^ self.c2_xor_key)
                c2 = re.findall("\{.*\}", decrypted)
                if c2:
                    self.mark_ioc("c2", c2[0], process["process_name"])

        if url:
            if re.findall(self.url_re, url):
                self.mark_ioc("url", url, process["process_name"])

        return self.has_marks()
