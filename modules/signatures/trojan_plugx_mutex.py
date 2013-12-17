from lib.cuckoo.common.abstracts import Signature

class BadBadMalware(Signature):
	name = "PlugX_Mutex"
	description = "Creates a mutex known to be associated with PlugX"
	severity = 3
	categories = ["trojan"]
	families = ["PlugX"]
	authors = ["securitykitten"]
	minimum = "0.5"

	def run(self):
		flag = False
		for item in self.mutex_list:
			if self.check_mutex(item):
				flag = True        
		return flag 

	mutex_list = ["StartInstall",
		"DoInstPrepare"
	]
