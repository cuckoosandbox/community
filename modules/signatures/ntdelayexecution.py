from lib.cuckoo.common.abstracts import Signature

class NtDelayExecution(Signature):

    name = "ntdelayexecution"
    description = "Delays execution more than threshold (default 1 min)"
    severity = 2
    categories = ["generic"]
    authors = ["Thomas Andersen"]

    def run(self, results):
        threshold = 60000
        delaytime = 0
        for process in results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "NtDelayExecution":
                   delaytime+=int(call["arguments"][0]["value"])
                   if delaytime >= threshold:
                       return True

        return False

