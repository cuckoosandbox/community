# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature
import re

class FakeUserAgent(Signature):
    name = "fake_user_agent"
    description = "Steals confidential information through a fake User Agent"
    severity = 3
    categories = ["H.worm"]
    authors = ["Biagio Tagliaferro"]
    minimum = "2.0"

    enabled = True

    def on_complete(self):
        for get_request in self.get_net_http():

            user_agent = str(get_request.get('user-agent'))

            if self.checkUserAgent(user_agent) :
                stolenFields = self.getFakeUserAgentFields(user_agent)
                self.mark_ioc("http", stolenFields)

        return self.get_net_http()

    def checkUserAgent(self, fake_ua):
        if re.search("|", fake_ua):
            return True
        else :
            return False

    
    def getFakeUserAgentFields(self, fake_ua) :
        stolenFields = fake_ua.split('<|>')
        
        # Bot identifier (based off configurable string in builder & volume serial number)
        botIdentifier = stolenFields[0]
        
        # Computer name
        computerName = stolenFields[1]
        
        # Username
        username = stolenFields[2]
        
        # Operating system information
        os = stolenFields[3]
        
        # Bot version
        botVersion = stolenFields[4]
        
        # Antivirus information (Default value 'nan-av')
        antivirusInfo = stolenFields[5]
        
        # USB spreading [true/false] with date obtained from bot's registry entry.
        usbSpreading = stolenFields[6]

        result = ""
        result += "Analyzed file stole some private data. "
        result += "Bot Identifier: " +botIdentifier+ " - "
        result += "Computer Name: " +computerName+ " - "
        result += "Username: " +username+ " - "
        result += "Operating System: " +os+ " - "
        result += "Bot Version: " +botVersion+ " - "
        result += "Antivirus Info: " +antivirusInfo+ " - "
        result += "USB Spreading: " +usbSpreading
        
        return result
