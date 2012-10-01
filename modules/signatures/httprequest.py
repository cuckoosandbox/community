import re

from lib.cuckoo.common.abstracts import Signature

class httprequest(Signature):
    name = "httprequest"
    description = "Performes a HTTP request"
    severity = 2
    categories = ["generic"]
    authors = ["Thomas Birn"]
    minimum = "0.4.2"

    def run(self, results):
        	
        for key in results["network"]['http']:
		if key:
			return True
	   
	
		
        
        return False