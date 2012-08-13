from lib.cuckoo.common.abstracts import Signature

class Flame(Signature):
    name = "flame"
    description = "Shows some indicators associated with the Flame malware"
    severity = 3
    references = ["http://www.crysys.hu/skywiper/skywiper.pdf",
                  "http://www.securelist.com/en/blog/208193522/The_Flame_Questions_and_Answers",
                  "http://www.certcc.ir/index.php?name=news&file=article&sid=1894"]
    categories = ["malware", "targeted"]
    authors = ["nex"]
    minimum = "0.4.1"

    def run(self, results):
        for mutex in results["behavior"]["summary"]["mutexes"]:
            if mutex.startswith("__fajb") or mutex.startswith("DVAAccessGuard") or "mssecuritymgr" in mutex:
                self.data.append({"mutex" : mutex})
                return True

        for file_name in results["behavior"]["summary"]["files"]:
            if "\\Microsoft Shared\\MSSecurityMgr\\" in file_name or "Ef_trace.log" in file_name:
                self.data.append({"file": file_name})
                return True

        return False
