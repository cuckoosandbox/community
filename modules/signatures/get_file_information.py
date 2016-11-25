from lib.cuckoo.common.abstracts import Signature

from common.win32api import detect

class GetFileInformation(Signature):
    name = "get_file_information"
    description = "Process that gets information on a file."
    severity = 1
    authors = ["Matthew Bradbury <matt-bradbury(at)live(dot)co(dot)uk>"]
    category = ["API Search"]

    references = ["http://www.mamounalazab.com/download/4186a052.pdf",
                  "http://msdn.microsoft.com/en-us/library/windows/desktop/aa364232%28v=vs.85%29.aspx"]

    apis = {"GetBinaryType", "GetCompressed", "FileSize", "GetCompressedFile", "SizeTransacted",
            "GetFileAttributes", "GetFileAttributesEx", "GetFileAttributes", "Transacted",
            "GetFileBandwidth", "Reservation", "GetFileInformation", "ByHandle", "GetFileInformation",
            "ByHandleEx", "GetFileSize", "GetFileSizeEx, GetFileType", "GetFinalPathName", "ByHandle",
            "GetFullPathName", "GetFullPathName", "Transacted", "GetLongPathName",
            "GetLongPathName", "Transacted", "GetShortPathName", "GetTempFileName", "GetTempPath"
           }

    def run(self, results):
        return detect(self, results)
        

