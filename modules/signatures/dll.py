from lib.cuckoo.common.abstracts import Signature

from common.win32api import detect

class Dll(Signature):
    name = "dll"
    description = "Process that uses DLL functions."
    severity = 1
    authors = ["Matthew Bradbury <matt-bradbury(at)live(dot)co(dot)uk>"]
    category = ["API Search"]

    references = ["http://msdn.microsoft.com/en-us/library/windows/desktop/ms682599%28v=vs.85%29.aspx"]

    apis = {"AddDllDirectory", "DisableThreadLibraryCalls", "DllMain", "FreeLibrary", "FreeLibraryAndExitThread", 
            "GetDllDirectory", "GetModuleFileName", "GetModuleHandle", "GetModuleHandleEx", "GetProcAddress", 
            "LoadLibrary", "LoadLibraryEx", "LoadModule", "LoadPackagedLibrary", "RemoveDllDirectory", 
            "SetDefaultDllDirectories", "SetDllDirectory"
           }

    def run(self, results):
        return detect(self, results)


