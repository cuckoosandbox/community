from lib.cuckoo.common.abstracts import Signature

class InstallsWinpcap(Signature):
    name = "installswinpcap"
    description = "Installs WinPCAP (Network Sniffer)"
    severity = 3
    categories = ["generic"]
    authors = ["Thomas Birn"]
    minimum = "0.4.2"
	
    files = [
        ".*\\\\packet.dll",
		".*\\\\npf.sys",
		".*\\\\wpcap.dll",
	
	]

    def run(self, results):
        for file_name in results["behavior"]["summary"]["files"]:
            for indicator in files:
                regexp = re.compile(indicator, re.IGNORECASE)
                if regexp.match(file_name):
                    self.data.append({"file" : file_name})
                    return True

        return False