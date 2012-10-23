from lib.cuckoo.common.abstracts import Signature

class KnownVirustotal(Signature):
    name = "known_virustotal"
    description = "File has been identified by at least one AntiVirus on VirusTotal as malicious"
    severity = 3
    categories = ["antivirus"]
    authors = ["Michael Boman"]

    def run(self, results):
        if "virustotal" in results:
            if "positives" in results["virustotal"]:
                if results["virustotal"]["positives"] > 0:
                    return True

        return False
