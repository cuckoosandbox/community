import re
import zlib
from cuckoo.common.abstracts import Extractor

class Powerfun(Extractor):
    yara_rules = "Powerfun"

    def handle_yara(self, filepath, match):
        sc = match.string("Shellcode", 0)
        argre = re.compile("FromBase64String\(['\"]([^)]+)['\"]\)")
        arg = argre.search(sc)
        if arg:
            self.push_shellcode(
                zlib.decompress(
                    arg.group(1).replace("'", "").decode('base64'),
                    16 + zlib.MAX_WBITS
                )
            )
