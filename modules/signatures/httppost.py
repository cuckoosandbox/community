import re

from lib.cuckoo.common.abstracts import Signature

class httppost(Signature):
    name = "httppost"
    description = "Performes a HTTP POST"
    severity = 3
    categories = ["generic"]
    authors = ["Thomas Birn"]
    minimum = "0.4.2"

    def run(self, results):
		if results["network"]:        	
			for http in results["network"]['http']:
				if http["method"] == "POST":
					self.data.append({"url" : http["uri"], "data" : http["body"]})
					return True
		
        return False