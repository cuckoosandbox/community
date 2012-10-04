import re

from lib.cuckoo.common.abstracts import Signature

class DisableTaskRegedit(Signature):
    name = "disabletaskregedit"
    description = "Disables Windows registry editor"
    severity = 3
    categories = ["generic"]
    authors = ["Thomas Birn"]
    minimum = "0.4.2"

    def run(self, results):
    indicator = ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System"


	value = "disableregistrytools"

        for key in results["behavior"]["summary"]["keys"]:
            regexp = re.compile(indicator, re.IGNORECASE)
            if regexp.match(key):
                    
			    for process in results["behavior"]["processes"]:
				    for call in process["calls"]:				
					    for argument in call["arguments"]:
						    if value == argument['value']:
						        self.data.append({"value" : value})
							    return True
        return False