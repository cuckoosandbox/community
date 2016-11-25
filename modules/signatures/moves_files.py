from lib.cuckoo.common.abstracts import Signature

from common.win32api import detect

class MovesFiles(Signature):
    name = "moves_files"
    description = "Process that moves files."
    severity = 1
    authors = ["Matthew Bradbury <matt-bradbury(at)live(dot)co(dot)uk>"]
    category = ["API Search"]

    references = ["http://www.mamounalazab.com/download/4186a052.pdf",
                  "http://msdn.microsoft.com/en-us/library/windows/desktop/aa364232%28v=vs.85%29.aspx"]

    apis = {"MoveFile", "MoveFileEx", "MoveFileTransacted", "MoveFileWithProgress"}

    def run(self, results):
        return detect(self, results)
        

