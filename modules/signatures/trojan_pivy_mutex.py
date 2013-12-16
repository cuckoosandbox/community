from lib.cuckoo.common.abstracts import Signature

class BadBadMalware(Signature):
	name = "PIVY_Mutex"
	description = "Creates a mutex known to be associated with Poison Ivy"
	severity = 3
	categories = ["trojan"]
	families = ["Poison Ivy"]
	authors = ["securitykitten"]
	minimum = "0.5"

	def run(self):
		flag = False
		for item in self.mutex_list:
			if self.check_mutex(item):
				flag = True        
		return flag 

	mutex_list = ["?????????",
		"0!VoqA.I4",
		")1VoqA.I4",
		"2314().A",
		")24342342",	
		"88796996",
		"(###9)###",
		"9!VoqA.I4",
		"(aoqa.I4",
		"B_&5rgr^#",
		")BBoqB.I1",
		"MutexVoqA.I4",
		")!PoqA.I4",
		"!(ProC1",
		")!RoqC.I2",
		")!V0qA.I5",
		")!V1qA.I4",
		")!VbqA.I3",
		"(!VobA.I4",
		")!Vo&F.I4",
		")!Voq",
		")!Voq3sa",
		")!Voqa.",
		")!VoqA.",
		")!VoqA.0&",
		")!VoqA.03",
		")!VoqA.11",
		")!VoqA.12",
		"!)VoqA14",
		")!VoqA.14",
		"VoqA.14",
		")!VoqA.15",
		")!VoqA.I",
		"(!VoqA.I",
		")!VoqA.I",
		")!VoqA.I0",
		")!VoqA.I1",
		")!VoqA.I2",
		"(!VoqA.I3",
		")!VoqA.I3",
		")!voqA.i4",
		")!voqA.I4",
		")!Voqa.I4",
		")!VoqA.i4",
		"(!VoqA.I4",
		")!VoqA>I4",
		")!VoqA.I4",
		")\"VoqA.I4",
		")VoqA.I4",
		")!VoQA.I4",
		")!VOqA.i4",
		")!VOqA.I4",
		")!VoqA.i5",
		")!VoqA.I5",
		")!VoqA.I9",
		")!VoqA.Ik",
		")!VoqA.It",
		")!VoqS.I1",
		")!VplK.I4",
		")!V_qA.I4",
		")!VQqA.I4",
		")!VXqA.l4",
		")!x0nE.i4",
		")!YoqJ.I4",
		"Zero"
	]
