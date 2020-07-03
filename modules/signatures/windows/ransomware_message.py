# Copyright (C) 2016 Kevin Ross
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

try:
    import re2 as re
except ImportError:
    import re

indicators = [
    "your files", "your data", "your documents", "restore files",
    "restore data", "restore the files", "restore the data", "recover files",
    "recover data", "recover the files", "recover the data", "has been locked",
    "pay fine", "pay a fine", "pay the fine", "decrypt", "encrypt",
    "recover files", "recover data", "recover them", "recover your",
    "recover personal", "bitcoin", "secret server", "secret internet server",
    "install tor", "download tor", "tor browser", "tor gateway",
    "tor-browser", "tor-gateway", "torbrowser", "torgateway", "torproject.org",
    "ransom", "bootkit", "rootkit", "payment", "victim", "AES128", "AES256",
    "AES 128", "AES 256", "AES-128", "AES-256", "RSA1024", "RSA2048",
    "RSA4096", "RSA 1024", "RSA 2048", "RSA 4096", "RSA-1024", "RSA-2048",
    "RSA-4096", "private key", "personal key", "your code", "private code",
    "personal code", "enter code", "your key", "unique key"
]

class RansomwareMessage(Signature):
    name = "ransomware_message"
    description = "Writes a potential ransom message to disk"
    severity = 3
    categories = ["ransomware"]
    authors = ["Kevin Ross"]
    minimum = "2.0.4"

    safelistprocs = [
        "iexplore.exe", "firefox.exe", "chrome.exe", "safari.exe",
        "acrord32.exe", "acrord64.exe", "wordview.exe", "winword.exe",
        "excel.exe", "powerpnt.exe", "outlook.exe", "mspub.exe"
    ]

    filter_apinames = set(["NtWriteFile"])

    def on_call(self, call, process):
        if process["process_name"].lower() not in self.safelistprocs:
            buff = call["arguments"]["buffer"].lower()
            if len(buff) >= 128 and (call["arguments"]["filepath"].endswith(".txt") or call["arguments"]["filepath"].endswith(".htm") or call["arguments"]["filepath"].endswith(".html")):
                patterns = "|".join(indicators)
                if len(re.findall(patterns, buff)) > 1:
                    self.mark_call()

    def on_complete(self):
        return self.has_marks()

class RansomwareMessageOCR(Signature):
    name = "ransomware_message_ocr"
    description = "Displays a potential ransomware message to the user (check screenshots)"
    severity = 3
    categories = ["ransomware", "ocr"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    # NOTE: This requires OCR analysis to be correctly setup.
    # Enable in processing.conf after following this guide for Ubuntu or
    # relevant guide for your OS
    # https://www.linux.com/blog/using-tesseract-ubuntu

    def on_complete(self):
        for screenshot in self.get_results("screenshots", []):
            if "ocr" in screenshot:
                ocr = screenshot["ocr"].lower()
                patterns = "|".join(indicators)
                if len(re.findall(patterns, ocr)) > 1:
                    self.mark_ioc("message", ocr)

        return self.has_marks()
