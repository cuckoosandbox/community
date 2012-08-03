from lib.cuckoo.common.abstracts import Signature

from common.win32api import detect

class ChangesFileAttributes(Signature):
    name = "modifies_file_attributes"
    description = "Process that modified file attributes."
    severity = 1
    authors = ["Matthew Bradbury <matt-bradbury(at)live(dot)co(dot)uk>"]
    category = ["API Search"]

    references = ["http://www.mamounalazab.com/download/4186a052.pdf",
                  "http://msdn.microsoft.com/en-us/library/windows/desktop/aa364232%28v=vs.85%29.aspx"]

    apis = {"SetFileApisToANSI", "SetFileApisToOEM", "SetFileAttributes",
            "SetFileAttributesTransacted", "SetFileBandwidthReservation",
            "SetFileInformationByHandle", "SetFileShortName", "SetFileValidData"
           }

    def run(self, results):
        return detect(self, results)
        

