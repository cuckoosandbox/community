from lib.cuckoo.common.abstracts import Signature

class CreatesAutorunInf(Signature):
    name = "createsautoruninf"
    description = "Creates an autorun.inf file"
    severity = 2
    categories = ["generic"]
    authors = ["Thomas Birn"]
    minimum = "0.4.1"

    def run(self, results):
        for file_name in results["behavior"]["summary"]["files"]:
            if "autorun.inf" in file_name:
                self.data.append({"file": file_name})
                return True

        return False