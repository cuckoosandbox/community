from lib.cuckoo.common.abstracts import Signature

from common.win32api import detect

class ReadOrWriteFiles(Signature):
    name = "reads_or_writes_files"
    description = "Process that reads or writes to files."
    severity = 1
    authors = ["Matthew Bradbury <matt-bradbury(at)live(dot)co(dot)uk>"]
    category = ["API Search"]

    references = ["http://www.mamounalazab.com/download/4186a052.pdf",
                  "http://msdn.microsoft.com/en-us/library/windows/desktop/aa364232%28v=vs.85%29.aspx"]

    apis = {"OpenFile", "OpenFileById", "ReOpenFile", "ReplaceFile", "WriteFile", "CreateFile", "CloseHandle"}

    def run(self, results):
        return detect(self, results)
        

