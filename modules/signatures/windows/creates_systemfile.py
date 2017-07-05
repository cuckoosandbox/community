from lib.cuckoo.common.abstracts import Signature

class CreatesSystemFiles(Signature):
    name = "creates_system_files"
    description = "Creates a file in the Windows system directory"
    severity = 3
    categories = ["generic"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    indicators = [
        ".*\\\\Windows\\\\System\\\\.*",
        ".*\\\\Windows\\\\System32\\\\.*",
        ".*\\\\Windows\\\\SysWOW64\\\\.*",
    ]

    def on_complete(self):
        for indicator in self.indicators:
            for filepath in self.check_file(pattern=indicator, actions=["file_written"], regex=True, all=True):
                self.mark_ioc("file", filepath)
 
        return self.has_marks()
