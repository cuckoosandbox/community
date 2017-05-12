from lib.cuckoo.common.abstracts import Signature

class CheckDebugger(Signature):
    name = "check_debugger"
    description = "Checks if a debugger is present"
    severity = 2
    categories = ["generic"]
    authors = ["FDD @ Cuckoo Sandbox"]
    minimum = "2.0"

    filter_apinames = "IsDebuggerPresent"

    def on_call(self, call, process):
        self.mark_call()
        return True
