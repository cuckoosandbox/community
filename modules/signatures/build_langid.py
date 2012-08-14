#Detects Russian, Chinese, Polish, Serbian, Croation, Czeck, Slovak, Albanian, Romanian LangIDs
#Modify this to look for any LangID, more info here http://msdn.microsoft.com/en-us/library/windows/desktop/aa381058%28v=vs.85%29.aspx
from lib.cuckoo.common.abstracts import Signature

class BuildLangID(Signature):
    name = "language_suspicious"
    description = "Suspicious Binary LangID"
    severity = 3
    author = "Benjamin K. and Kevin R."
    categories = ["generic"]

    def run(self, results):
        for translation in results["static"]["pe_versioninfo"]:
            if translation["name"]=="Translation": 
			if translation["value"].startswith("0x004") or translation["value"].startswith("0x0C04") or translation["value"].startswith("0x0804") or translation["value"].startswith("0x0419") or translation["value"].startswith("0x0404") or translation["value"].startswith("0x0415") or translation["value"].startswith("0x081A") or translation["value"].startswith("0x041A") or translation["value"].startswith("0x0405") or translation["value"].startswith("0x041B") or translation["value"].startswith("0x041C") or translation["value"].startswith("0x0418") or translation["value"].startswith("0x0417"): 
	              	  self.data.append({"translation" : translation})
                          return True

        return False
