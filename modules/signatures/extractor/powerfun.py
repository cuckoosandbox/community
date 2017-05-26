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
            # Powerfun invokes a second-stage PS script
            # This script is b64encoded and gziped
            script = zlib.decompress(
                arg.group(1).replace("'", "").decode('base64'),
                16 + zlib.MAX_WBITS
            )
            # The shellcode in the script is also b64 encoded
            arg = argre.search(script)
            if arg:
                self.push_shellcode(
                    arg.group(1).replace("'", "").decode('base64')
                )
