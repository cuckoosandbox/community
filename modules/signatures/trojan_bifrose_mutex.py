from lib.cuckoo.common.abstracts import Signature

class BadBadMalware(Signature):
	name = "Bifrose_Mutex"
	description = "Creates a mutex known to be associated with Bifrose"
	severity = 3
	categories = ["trojan"]
	families = ["Bifrose"]
	authors = ["securitykitten"]
	minimum = "0.5"

	def run(self):
		flag = False
		for item in self.mutex_list:
			if self.check_mutex(item):
				flag = True        
		return flag 

	mutex_list = ["Bif1234",
		"0ok3s",
		"0ok.s",
		"uxJLpe1m",
		"93nf3",
		"Op1mutx9",
		"bif1234",
		"uZCitk9XZ",
		"xdZ9kZ98",
		"0ok2s"
	]
