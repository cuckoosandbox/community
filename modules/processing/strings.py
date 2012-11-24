import os
import logging
from lib.cuckoo.common.utils import File
from lib.cuckoo.common.abstracts import Processing

class Strings(Processing):
    """Get printable characters from a file."""

    def run(self):
        """Run printable character gathering.
        @return: information dict.
        """
        self.key = "strings"
        strings = {}

        if not os.path.exists(self.file_path):
            return {}

        try:
            import subprocess
            """try to get ascii strings"""
            strings_process = subprocess.Popen(['strings', '-a', '-n10', self.file_path], stdout = subprocess.PIPE)
            ascii_strings = [item.strip() for item in strings_process.stdout.readlines()]

            """try to get unicode strings"""
            strings_process = subprocess.Popen(['strings', '-a', '-n10', '-el', self.file_path], stdout = subprocess.PIPE)
            unicode_strings = [item.strip() for item in strings_process.stdout.readlines()]
        except:
            log.warning("failed to extract printable characters, skip")
            return {}

        strings["ascii"] = ascii_strings
        strings["unicode"] = unicode_strings
        return strings
