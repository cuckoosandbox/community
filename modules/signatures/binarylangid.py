from lib.cuckoo.common.abstracts import Signature

class BuildLangID(Signature):
    name = "buildlangid"
    description = "Unconventionial binary language"
    severity = 2
    authors = ["Benjamin K.", "Kevin R.", "nex"]
    categories = ["generic"]

    def run(self, results):
        languages = [
            {"language" : "Arabic", "code" : "0x0401"},
            {"language" : "Bulgarian", "code" : "0x0402"},
            {"language" : "Traditional Chinese" , "code" : "0x0404"},
            {"language" : "Romanian", "code" : "0x0418"},
            {"language" : "Russian", "code" : "0x0419"},
            {"language" : "Croato-Serbian", "code" : "0x041A"},
            {"language" : "Slovak", "code" : "0x041B"},
            {"language" : "Albanian", "code" : "0x041C"},
            {"language" : "Turkish", "code" : "0x041F"},
            {"language" : "Simplified Chinese", "code" : "0x0804"},
            {"language" : "Hebrew", "code" : "0x040d"}
        ]

        if "pe_versioninfo" in results["static"]:
            for info in results["static"]["pe_versioninfo"]:
                if info["name"] == "Translation":
                    lang, charset = info["value"].strip().split(" ")
                    for language in languages:
                        if language["code"] == lang:
                            self.description += ": %s" % language["language"]
                            return True

        return False
