from lib.cuckoo.common.abstracts import Signature

from common.win32api import detect

class CopyOrDeleteFiles(Signature):
    name = "copy_or_delete_files"
    description = "Process that copies, creates or deletes files."
    severity = 1
    authors = ["Matthew Bradbury <matt-bradbury(at)live(dot)co(dot)uk>"]
    category = ["API Search"]

    references = ["http://www.mamounalazab.com/download/4186a052.pdf",
                  "http://msdn.microsoft.com/en-us/library/windows/desktop/aa364232%28v=vs.85%29.aspx"]

    apis = {"CloseHandle", "CopyFile", "CopyFileEx", "CopyFileTransacted", "CreateFile",
            "CreateFileTransacted", "CreateHardLink", "CreateHardLink", "Transacted",
            "CreateSymbolicLink", "CreateSymbolic", "LinkTransacted", "DeleteFile",
            "DeleteFileTransacted", "NtClose"
           }

    def run(self, results):
        return detect(self, results)
        

