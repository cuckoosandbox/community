# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ntpath
import re

from lib.cuckoo.common.abstracts import Signature

network_objects = [
    "microsoft.xmlhttp",
    "msxml2.serverxmlhttp",
    "msxml2.xmlhttp",
    "msxml2.serverxmlhttp.6.0",
    "winhttp.winhttprequest.5.1",
]

class OfficeCreateObject(Signature):
    name = "office_create_object"
    description = "Creates suspicious VBA object"
    severity = 3
    categories = ["vba"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "vbe6_CreateObject", "vbe6_GetObject"

    objects = {
        "adodb.stream": "file",
        "scripting.filesystemobject": "file",
        "shell.application": "process",
        "wscript.shell": "process",
    }

    # Include all globally defined network objects.
    objects.update(dict((_, "network") for _ in network_objects))

    descriptions = {
        "network": "May attempt to connect to the outside world",
        "file": "May attempt to write one or more files to the harddisk",
        "process": "May attempt to create new processes",
    }

    def on_call(self, call, process):
        objname = call["arguments"]["object_name"]
        if objname.lower() not in self.objects:
            return

        description = self.descriptions[self.objects[objname.lower()]]
        self.mark_ioc("com_class", objname, description)
        return True

class OfficeCheckProjectName(Signature):
    name = "office_check_project_name"
    description = "Office checks VB project name"
    severity = 1
    categories = ["vba"]
    authors = ["FDD", "Cuckoo Sandbox"]
    minimum = "2.0"

    filter_apinames = "vbe6_Invoke",

    def on_call(self, call, process):
        if call["arguments"]["funcname"] != "macroname":
            return

        self.mark_call()
        return True

class OfficeCountDirectories(Signature):
    name = "office_count_dirs"
    description = "Office document invokes CountDirectories (possible anti-sandbox)"
    severity = 2
    categories = ["vba"]
    authors = ["FDD @ Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "vbe6_Invoke",

    def on_call(self, call, process):
        if call["arguments"]["funcname"] != "CountDirectories":
            return

        self.mark_call()
        return True

class OfficeCheckVersion(Signature):
    name = "office_appinfo_version"
    description = "Office document checks Office version (possible anti-sandbox)"
    severity = 2
    categories = ["vba"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "vbe6_Invoke",

    def on_call(self, call, process):
        if not "args" in call["arguments"]:
            return

        if (call["arguments"]["funcname"] != "AppInfo" or
                call["arguments"]["args"][0] != 2):
            return

        self.mark_call()
        return True

class OfficeCheckWindow(Signature):
    name = "office_check_window"
    description = "Office document checks Office window size (possible anti-sandbox)"
    severity = 2
    categories = ["vba"]
    authors = ["FDD @ Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "vbe6_Invoke",

    def on_call(self, call, process):
        if not "args" in call["arguments"]:
            return

        if (call["arguments"]["funcname"] != "AppInfo" or
                call["arguments"]["args"][0] != 7):
            return

        self.mark_call()
        return True


class OfficeHttpRequest(Signature):
    name = "office_http_request"
    description = "Office document performs HTTP request (possibly to download malware)"
    severity = 5
    categories = ["vba"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "vbe6_Invoke",

    def on_call(self, call, process):
        # This checks if this instance method invocation belongs to
        # a known network class (e.g., "MSXML2.XMLHTTP").
        if call["flags"].get("this", "").lower() not in network_objects:
            return

        # The .Open method specifies the URL.
        if call["arguments"]["funcname"] != "Open":
            return

        # Usually ["GET", "url", False].
        if len(call["arguments"]["args"]) == 3:
            self.mark_ioc("payload_url", call["arguments"]["args"][1])
            return True

class OfficeRecentFiles(Signature):
    name = "office_recent_files"
    description = "Uses RecentFiles to determine whether it is running in a sandbox"
    severity = 4
    categories = ["vba"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "vbe6_Invoke",

    def on_call(self, call, process):
        if call["arguments"]["funcname"] == "RecentFiles":
            self.mark_call()
            return True
        
class OfficeVBAImport(Signature):
    name = "office_vba_api_import"
    description = "Imports API functions using VBA code"
    severity = 3
    categories = ["vba"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_apinames = "vbe6_Import",

    def on_call(self, call, process):
        self.mark_call()

    def on_complete(self):
        return self.has_marks()

class OfficeCreatesEPS(Signature):
    name = "office_creates_eps"
    description = "Office has created an Encapsulated Post Script (EPS) file indicative of a possible exploit"
    severity = 3
    categories = ["exploit", "office"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    office_procs = [
        "excel.exe",
        "outlook.exe",
        "powerpnt.exe",
        "powershell.exe",
        "winword.exe",
    ]

    filter_apinames = "NtWriteFile",

    def on_call(self, call, process):
        if process["process_name"].lower() in self.office_procs:           
            buf = call["arguments"]["buffer"]
            if buf.startswith("%!PS-Adobe-3.0 EPSF-3.0"):
                self.mark_call()
                
    def on_complete(self):
        return self.has_marks()

class HasOfficeEps(Signature):
    name = "has_office_eps"
    description = "Located potentially malicious Encapsulated Post Script (EPS) file"
    severity = 3
    categories = ["office"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        office = self.get_results("static", {}).get("office", {})
        if office.get("eps", []):
            for match in office.get("eps", []):
                self.mark_ioc("eps_string", match)
                           
        return self.has_marks()

class OfficeEpsStrings(Signature):
    name = "office_eps_strings"
    description = "Suspicious keywords embedded in an Encapsulated Post Script (EPS) file"
    severity = 3
    categories = ["office"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    keywords = [
        "longjmp", "NtCreateEvent", "NtProtectVirtualMemory", "VirtualProtect"
    ]

    def on_complete(self):
        office = self.get_results("static", {}).get("office", {})
        for s in office.get("eps", []):
            if s.strip() in self.keywords:
                self.mark_ioc("eps_string", s)

        return self.has_marks()

class OfficeIndirectCall(Signature):
    name = "office_indirect_call"
    description = "Office document has indirect calls"
    severity = 1
    categories = ["office"]
    authors = ["FDD @ Cuckoo Technologies"]
    minimum = "2.0"

    patterns = [
        "CallByName[^\r\n;']*",
    ]

    def on_complete(self):
        office = self.get_results("static", {}).get("office", {})
        if "macros" in office:
            for macro in office["macros"]:
                for pattern in self.patterns:
                    matches = re.findall(pattern, macro["deobf"])
                    for match in matches:
                        self.mark_ioc("Statement", match)
                    
            return self.has_marks()

class OfficeCheckName(Signature):
    name = "office_check_doc_name"
    description = "Office document checks it's own name"
    severity = 2
    categories = ["office"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"

    patterns = [
        "[^\n\r;']*Me.Name[^\n\r;']*",
    ]

    def on_complete(self):
        office = self.get_results("static", {}).get("office", {})
        if "macros" in office:
            for macro in office["macros"]:
                for pattern in self.patterns:
                    matches = re.findall(pattern, macro["deobf"])
                    for match in matches:
                        self.mark_ioc("Statement", match)
                    
            return self.has_marks()

class OfficePlatformDetect(Signature):
    name = "office_platform_detect"
    description = "Office document tries to detect platform"
    severity = 2
    categories = ["office"]
    authors = ["FDD @ Cuckoo Technologies"]
    minimum = "2.0"

    patterns = [
        "#If\s+(?:Not\s+)?Win32",
        "#If\s+Mac\s*=\s(?:1|0)"
    ]

    def on_complete(self):
        office = self.get_results("static", {}).get("office", {})
        if "macros" in office:
            for macro in office["macros"]:
                for pattern in self.patterns:
                    matches = re.findall(pattern, macro["deobf"])
                    for match in matches:
                        self.mark_ioc("Statement", match)
                    
            return self.has_marks()

class DocumentClose(Signature):
    name = "document_close"
    description = "Word document hooks document close"
    severity = 2
    categories = ["office"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        office = self.get_results("static", {}).get("office", {})
        if "macros" in office:
            for macro in office["macros"]:
                if "Sub Document_Close()" in macro["deobf"]:
                    return True

class DocumentOpen(Signature):
    name = "document_open"
    description = "Word document hooks document open"
    severity = 2
    categories = ["office"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        office = self.get_results("static", {}).get("office", {})
        if "macros" in office:
            for macro in office["macros"]:
                if "Sub Document_Open()" in macro["deobf"]:
                    return True

class OfficeMacro(Signature):
    name = "office_macro"
    description = "Office document contains one or more macros"
    severity = 2
    categories = ["office"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    def on_complete(self):
        office = self.get_results("static", {}).get("office", [])
        for macro in office["macros"]:
            self.mark(
                macro_filename=macro["filename"],
                macro_stream=macro["stream"],
            )

        return self.has_marks()

class DocumentEmbeddedObject(Signature):
    name = "document_embedded_object"
    description = "Document has embedded objects"
    severity = 2
    categories = ["office"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        office = self.get_results("static", {}).get("office", {})
        if not "objects" in office:
            return

        for filename, data in office["objects"].iteritems():
            self.mark(filename=filename, content=data)
        return self.has_marks()


class DocumentEmbeddedDangerousObject(Signature):
    name = "document_embedded_dangerous_object"
    description = "Document has a potentially dangerous embedded object"
    severity = 4
    categories = ["office"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"

    dangerous_extensions = [
        ".vbs", ".js", ".wsc", ".wsf", ".py", ".exe", ".dll",
        ".rb", ".hta"
    ]

    def on_complete(self):
        office = self.get_results("static", {}).get("office", {})
        if not "objects" in office:
            return

        for filename, data in office["objects"].iteritems():
            for ext in self.dangerous_extensions:
                if not filename or "unnamed_" in filename:
                    # Try to get embedded filenames
                    pathre = re.compile(r"(?:[a-zA-Z]\:|\\\\[\w\.]+\\[\w~.$]+)\\(?:[\w~]+\\\\?)*\w([\w.])+")
                    match = pathre.search(data)
                    if match:
                        filename = match.group(0)

                if ext in filename:
                    self.mark(filename=filename, content=data)

        return self.has_marks()

class OfficeVulnerableGuid(Signature):
    name = "office_vuln_guid"
    description = "GUIDs known to be associated with a CVE were requested (may be False Positive)"
    severity = 3
    categories = ["office"]
    authors = ["Niels Warnars @ Cuckoo Technologies"]
    minimum = "2.0"

    bad_guids = {
        "BDD1F04B-858B-11D1-B16A-00C0F0283628": "CVE-2012-0158",
        "996BF5E0-8044-4650-ADEB-0B013914E99C": "CVE-2012-0158",
        "C74190B6-8589-11d1-B16A-00C0F0283628": "CVE-2012-0158",
        "9181DC5F-E07D-418A-ACA6-8EEA1ECB8E9E": "CVE-2012-0158",
        "1EFB6596-857C-11D1-B16A-00C0F0283628": "CVE-2012-1856",
        "66833FE6-8583-11D1-B16A-00C0F0283628": "CVE-2012-1856",
        "1EFB6596-857C-11D1-B16A-00C0F0283628": "CVE-2013-3906",
        "DD9DA666-8594-11D1-B16A-00C0F0283628": "CVE-2014-1761",
        "00000535-0000-0010-8000-00AA006D2EA4": "CVE-2015-0097",
        "0E59F1D5-1FBE-11D0-8FF2-00A0D10038BC": "CVE-2015-0097",
        "05741520-C4EB-440A-AC3F-9643BBC9F847": "CVE-2015-1641",
        "A08A033D-1A75-4AB6-A166-EAD02F547959": "CVE-2015-1641",
        "F4754C9B-64F5-4B40-8AF4-679732AC0607": "CVE-2015-1641",
        "4C599241-6926-101B-9992-00000B65C6F9": "CVE-2015-2424",
        "44F9A03B-A3EC-4F3B-9364-08E0007F21DF": "CVE-2015-2424",
    }

    def on_complete(self):
        summary = self.get_results("behavior", {}).get("summary", {})
        for guid in summary.get("guid", []):
            if guid.upper() in self.bad_guids:
                self.mark_ioc("cve", self.bad_guids[guid.upper()])
        return self.has_marks()

class OfficeVulnModules(Signature):
    name = "office_vuln_modules"
    description = "Libraries known to be associated with a CVE were requested (may be False Positive)"
    severity = 3
    categories = ["office"]
    authors = ["Niels Warnars @ Cuckoo Technologies"]
    minimum = "2.0"

    bad_modules = {
        "ogl.dll": "CVE-2013-3906",
        "oart.dll": "CVE-2013-3906",
        "packager.dll": "CVE-2014-4114/6352",
        "olkloadr.dll": "CVE-2015-1641",
        "epsimp32.flt": "CVE-2015-2545",
    }

    def on_complete(self):
        summary = self.get_results("behavior", {}).get("summary", {})
        for module in summary.get("dll_loaded", []):
            module = ntpath.split(module)[1]
            if module.lower() in self.bad_modules:
                self.mark_ioc("cve", self.bad_modules[module.lower()])
        return self.has_marks()

class UnconventionalOfficeCodePage(Signature):
    name = "unconventional_office_code_page"
    description = "Office file uses an unconventional code page"
    severity = 2
    categories = ["office"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    codepages = [
        {"language" : "Arabic (ASMO 708)", "code" : "Code page: 708,"},
        {"language" : "Arabic (ASMO-449+, BCON V4)", "code" : "Code page: 709,"},
        {"language" : "Arabic - Transparent Arabic", "code" : "Code page: 710,"},
        {"language" : "Arabic (Transparent ASMO); Arabic (DOS)", "code" : "Code page: 720,"},
        {"language" : "OEM Baltic; Baltic (DOS)", "code" : "Code page: 775,"},
        {"language" : "OEM Cyrillic (primarily Russian)", "code" : "Code page: 855,"},
        {"language" : "OEM Turkish; Turkish (DOS)", "code" : "Code page: 857,"},
        {"language" : "OEM Arabic; Arabic (864)", "code" : "Code page: 864,"},
        {"language" : "OEM Russian; Cyrillic (DOS)", "code" : "Code page: 866,"},
        {"language" : "ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312)", "code" : "Code page: 936,"},
        {"language" : "ANSI/OEM Traditional Chinese (Taiwan; Hong Kong SAR, PRC); Chinese Traditional (Big5)", "code" : "Code page: 950,"},
        {"language" : "IBM EBCDIC Turkish (Latin 5)", "code" : "Code page: 1026,"},
        {"language" : "ANSI Cyrillic; Cyrillic (Windows)", "code" : "Code page: 1251,"},
        {"language" : "ANSI Turkish; Turkish (Windows)", "code" : "Code page: 1254,"},
        {"language" : "ANSI Arabic; Arabic (Windows)", "code" : "Code page: 1256,"},
        {"language" : "ANSI/OEM Vietnamese; Vietnamese (Windows)", "code" : "Code page: 1257,"},
        {"language" : "MAC Traditional Chinese (Big5); Chinese Traditional (Mac)", "code" : "Code page: 10002,"},
        {"language" : "Arabic (Mac)", "code" : "Code page: 10004,"},
        {"language" : "Cyrillic (Mac)", "code" : "Code page: 10007,"},
        {"language" : "MAC Simplified Chinese (GB 2312); Chinese Simplified (Mac)", "code" : "Code page: 10008,"},
        {"language" : "Romanian (Mac)", "code" : "Code page: 10010,"},
        {"language" : "Turkish (Mac)", "code" : "Code page: 10017,"},
        {"language" : "Croatian (Mac)", "code" : "Code page: 10082,"},
        {"language" : "CNS Taiwan; Chinese Traditional (CNS)", "code" : "Code page: 20000,"},
        {"language" : "Eten Taiwan; Chinese Traditional (Eten)", "code" : "Code page: 20002,"},
        {"language" : "IBM EBCDIC Arabic", "code" : "Code page: 20420,"},
        {"language" : "Russian (KOI8-R); Cyrillic (KOI8-R)", "code" : "Code page: 20866,"},
        {"language" : "IBM EBCDIC Cyrillic Russian", "code" : "Code page: 20880,"},
        {"language" : "IBM EBCDIC Turkish", "code" : "Code page: 20905,"},
        {"language" : "Simplified Chinese (GB2312); Chinese Simplified (GB2312-80)", "code" : "Code page: 20936,"},
        {"language" : "IBM EBCDIC Cyrillic Serbian-Bulgarian", "code" : "Code page: 21025,"},
        {"language" : "Ukrainian (KOI8-U); Cyrillic (KOI8-U)", "code" : "Code page: 21866,"},
        {"language" : "ISO 8859-4 Baltic", "code" : "Code page: 28594,"},
        {"language" : "ISO 8859-5 Cyrillic", "code" : "Code page: 28595,"},
        {"language" : "ISO 8859-6 Arabic", "code" : "Code page: 28596,"},
        {"language" : "ISO 8859-9 Turkish", "code" : "Code page: 28599,"},
        {"language" : "ISO 8859-13 Estonian", "code" : "Code page: 28603,"},
        {"language" : "ISO 2022 Simplified Chinese; Chinese Simplified (ISO 2022)", "code" : "Code page: 50227,"},
        {"language" : "ISO 2022 Traditional Chinese", "code" : "50229,"},
        {"language" : "EBCDIC Simplified Chinese Extended and Simplified Chinese", "code" : "Code page: 50935,"},
        {"language" : "EBCDIC Simplified Chinese", "code" : "Code page: 50936,"},
        {"language" : "EUC Traditional Chinese", "code" : "Code page: 51950,"},
        {"language" : "HZ-GB2312 Simplified Chinese; Chinese Simplified (HZ)", "code" : "Code page: 52936,"},
        {"language" : "GB18030 Simplified Chinese (4 byte); Chinese Simplified (GB18030)", "code" : "Code page: 54936,"},
        {"language" : "ISCII Devanagari", "code" : "Code page: 57002,"},
        {"language" : "ISCII Bangla", "code" : "Code page: 57003,"},
        {"language" : "ISCII Tamil", "code" : "Code page: 57004,"},
        {"language" : "ISCII Telugu", "code" : "Code page: 57005,"},
        {"language" : "ISCII Assamese", "code" : "Code page: 57006,"},
        {"language" : "ISCII Odia", "code" : "Code page: 57007,"},
        {"language" : "ISCII Kannada", "code" : "Code page: 57008,"},
        {"language" : "ISCII Malayalam", "code" : "Code page: 57009,"},
        {"language" : "ISCII Gujarati", "code" : "Code page: 57010,"},
        {"language" : "ISCII Punjabi", "code" : "Code page: 57011,"}
    ]

    def on_complete(self):
        filetype = self.get_results("target", {})["file"]["type"]
        name = self.get_results("target", {})["file"]["name"]
        for codepage in self.codepages:
            if codepage["code"] in filetype:
                self.mark(
                    filename=name,
                    codepage_language=codepage["language"],
                )
            # Check dropped files too in case dropped from Internet, another office document embedded in PDF or created as a decoy document from an exploit etc.
            for dropped in self.get_results("dropped", []):
                if "filepath" in dropped:
                    droppedtype = dropped["type"]
                    droppedname = dropped["name"]
                    if codepage["code"] in droppedtype:
                        self.mark(
                            dropped_filename=droppedname,
                            codepage_language=codepage["language"],
                        )
            
        return self.has_marks()

class OfficeNoEditTime(Signature):
    name = "office_no_edit_time"
    description = "Office file has no edit time indicating it may have been automatically generated"
    severity = 1
    categories = ["office"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    def on_complete(self):
        filetype = self.get_results("target", {})["file"]["type"]
        name = self.get_results("target", {})["file"]["name"]
        if "Total Editing Time: 00:00" in filetype:
            self.mark(
                filename=name,
                filetype_details=filetype,
            )
            for dropped in self.get_results("dropped", []):
                if "filepath" in dropped:
                    droppedtype = dropped["type"]
                    droppedname = dropped["name"]
                    if "Total Editing Time: 00:00" in droppedtype:
                        self.mark(
                            dropped_filename=droppedname,
                            dropped_filetype_details=filetype,
                        )
            
        return self.has_marks()

class OfficeNoContent(Signature):
    name = "office_no_content"
    description = "Office file has no word content indicating it may have been automatically generated"
    severity = 1
    categories = ["office"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    def on_complete(self):
        filetype = self.get_results("target", {})["file"]["type"]
        name = self.get_results("target", {})["file"]["name"]
        if "Number of Words: 0, Number of Characters: 0," in filetype:
            self.mark(
                filename=name,
                filetype_details=filetype,
            )
            for dropped in self.get_results("dropped", []):
                if "filepath" in dropped:
                    droppedtype = dropped["type"]
                    droppedname = dropped["name"]
                    if "Number of Words: 0, Number of Characters: 0," in droppedtype:
                        self.mark(
                            dropped_filename=droppedname,
                            dropped_filetype_details=filetype,
                        )
            
        return self.has_marks()
