from lib.cuckoo.common.abstracts import Signature

from common.win32api import detect

class Pipes(Signature):
    name = "performs_network_activity"
    description = "Process that uses pipes."
    severity = 1
    authors = ["Matthew Bradbury <matt-bradbury(at)live(dot)co(dot)uk>"]
    category = ["API Search"]

    references = ["http://msdn.microsoft.com/en-us/library/windows/desktop/aa365781%28v=vs.85%29.aspx"]

    apis = {"CallNamedPipe", "ConnectNamedPipe", "CreateNamedPipe", "CreatePipe", 
            "DisconnectNamedPipe", "GetNamedPipeClientComputerName", "GetNamedPipeClientProcessId", 
            "GetNamedPipeClientSessionId", "GetNamedPipeHandleState", "GetNamedPipeInfo", 
            "GetNamedPipeServerProcessId", "GetNamedPipeServerSessionId", 
            "PeekNamedPipe", "SetNamedPipeHandleState", "TransactNamedPipe", "WaitNamedPipe"
           }

    def run(self, results):
        return detect(self, results)
        

