from lib.cuckoo.common.abstracts import Signature

class BadBadMalware(Signature):
	name = "Travnet_Mutex"
	description = "Creates a mutex known to be associated with Travnet"
	severity = 3
	categories = ["trojan"]
	families = ["Travnet"]
	authors = ["securitykitten"]
	minimum = "0.5"

	def run(self):
		flag = False
		for item in self.mutex_list:
			if self.check_mutex(item):
				flag = True        
		return flag 

	mutex_list = ["Assassin",
		"INSTALL SERVICES NOW!",
		"NetTravler Is Running!",
		"NT-2012 Is Running!",
		"NetTravler2012 Is Running!"
	]
