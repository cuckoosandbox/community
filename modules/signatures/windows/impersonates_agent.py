# Copyright (C) 2010-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class ImpersonatesUserAgent(Signature):
    name = "impersonates_user_agent"
    description = "Reads the systems User Agent and subsequently uses it in its own requests"
    authors = ["Cuckoo Technologies"]
    severity = 2
    categories = ["stealth"]
    minimum = "2.0"

    filter_apinames = "ObtainUserAgentString", "InternetOpenA", "InternetOpenW"
    
    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.system_user_agent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)"
        
    def on_call(self, call, process):
        api = call["api"]
        agent = call["arguments"]["user_agent"]
        if api == "ObtainUserAgentString":
            #self.system_user_agent = agent
            pass
        elif agent == self.system_user_agent:
            self.mark_call()
            return True
