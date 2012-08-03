from lib.cuckoo.common.abstracts import Signature

from common.win32api import detect

class Hooks(Signature):
    name = "hooks"
    description = "Process that hooks into other processes or devices."
    severity = 2
    authors = ["Matthew Bradbury <matt-bradbury(at)live(dot)co(dot)uk>"]
    category = ["API Search"]

    references = ["http://msdn.microsoft.com/en-us/library/windows/desktop/ff468842%28v=vs.85%29.aspx"]

    apis = {"CallMsgFilter", "CallNextHookEx", "CallWndProc", "CallWndRetProc", "CBTProc", 
            "DebugProc", "ForegroundIdleProc", "GetMsgProc", "JournalPlaybackProc", 
            "JournalRecordProc", "KeyboardProc", "LowLevelKeyboardProc", "LowLevelMouseProc", 
            "MessageProc", "MouseProc", "SetWindowsHookEx", "ShellProc", 
            "SysMsgProc", "UnhookWindowsHookEx"
           }

    def run(self, results):
        return detect(self, results)


