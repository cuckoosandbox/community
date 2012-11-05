# Copyright (C) 2012 Michael Boman (@mboman)
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

# Based on information from http://antivirus.about.com/od/windowsbasics/tp/autostartkeys.htm
# Based on locations from Sysinternals (Microsoft) "autoruns.exe" http://technet.microsoft.com/en-us/sysinternals/bb963902.aspx

import re

from lib.cuckoo.common.abstracts import Signature

class Autorun(Signature):
    name = "autorun"
    description = "Hooks to start automatically at next boot"
    severity = 3
    categories = ["generic"]
    authors = ["Michael Boman"]
    minimum = "0.4.1"

    def run(self, results):
        registryEntries = [
            ".*\\\\SOFTWARE\\\\Classes\\\\.*\\\\ShellEx\\\\ContextMenuHandlers",
            ".*\\\\SOFTWARE\\\\Classes\\\\.*\\\\ShellEx\\\\PropertySheetHandlers",
            ".*\\\\SOFTWARE\\\\Classes\\\\\.cmd",
            ".*\\\\SOFTWARE\\\\Classes\\\\\.exe",
            ".*\\\\SOFTWARE\\\\Classes\\\\AllFileSystemObjects\\\\ShellEx\\\\ContextMenuHandlers",
            ".*\\\\SOFTWARE\\\\Classes\\\\AllFileSystemObjects\\\\ShellEx\\\\DragDropHandlers",
            ".*\\\\SOFTWARE\\\\Classes\\\\AllFileSystemObjects\\\\ShellEx\\\\PropertySheetHandlers",
            ".*\\\\SOFTWARE\\\\Classes\\\\CLSID\\\\.*\\\\Instance",
            ".*\\\\SOFTWARE\\\\Classes\\\\Directory\\\\Background\\\\ShellEx\\\\ContextMenuHandlers",
            ".*\\\\SOFTWARE\\\\Classes\\\\Directory\\\\ShellEx\\\\ContextMenuHandlers",
            ".*\\\\SOFTWARE\\\\Classes\\\\Directory\\\\Shellex\\\\CopyHookHandlers",
            ".*\\\\SOFTWARE\\\\Classes\\\\Directory\\\\Shellex\\\\DragDropHandlers",
            ".*\\\\SOFTWARE\\\\Classes\\\\Directory\\\\Shellex\\\\PropertySheetHandlers",
            ".*\\\\SOFTWARE\\\\Classes\\\\Exefile\\\\Shell\\\\Open\\\\Command\\\\(Default)",
            ".*\\\\SOFTWARE\\\\Classes\\\\Filter",
            ".*\\\\SOFTWARE\\\\Classes\\\\Folder\\\\ShellEx\\\\ContextMenuHandlers",
            ".*\\\\SOFTWARE\\\\Classes\\\\Folder\\\\ShellEx\\\\DragDropHandlers",
            ".*\\\\SOFTWARE\\\\Classes\\\\Folder\\\\ShellEx\\\\ExtShellFolderViews",
            ".*\\\\SOFTWARE\\\\Classes\\\\Folder\\\\ShellEx\\\\PropertySheetHandlers",
            ".*\\\\SOFTWARE\\\\Classes\\\\Folder\\\\Shellex\\\\ColumnHandlers",
            ".*\\\\SOFTWARE\\\\Classes\\\\Protocols\\\\Filter",
            ".*\\\\SOFTWARE\\\\Classes\\\\Protocols\\\\Handler",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Active Setup\\\\Installed Components",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Active Setup\\\\Installed Components\\\\",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Command Processor\\\\Autorun",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Ctf\\\\LangBarAddin",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Internet Explorer\\\\Desktop\\\\Components",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Internet Explorer\\\\Explorer Bars",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Internet Explorer\\\\Extensions",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Internet Explorer\\\\Toolbar",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Internet Explorer\\\\UrlSearchHooks",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows CE Services\\\\AutoStartOnConnect",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows CE Services\\\\AutoStartOnDisconnect",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\"
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Drivers32",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Terminal Server\\\\Install\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Terminal Server\\\\Install\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Runonce",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\Appinit_Dlls",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\IconServiceLib",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\Load",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\Run",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\AppSetup",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\GinaDLL",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\LsaStart",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\Notify",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\SaveDumpStart",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\ServiceControllerStart",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\Shell",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\System",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\Taskman",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\UIHost",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\Userinit",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\VmApplet",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Browser Helper Objects",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\SharedTaskScheduler",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\ShellExecuteHooks",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\ShellIconOverlayIdentifiers",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Group Policy\\\\Scripts\\\\Shutdown",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Group Policy\\\\Scripts\\\\Startup",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\SYSTEM\\\\Shell",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServices",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServicesOnce",
            ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\ShellServiceObjectDelayLoad",
            ".*\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows\\\\SYSTEM\\\\Scripts\\\\Logoff",
            ".*\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows\\\\SYSTEM\\\\Scripts\\\\Logon",
            ".*\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows\\\\SYSTEM\\\\Scripts\\\\Shutdown",
            ".*\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows\\\\SYSTEM\\\\Scripts\\\\Startup",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Classes\\\\*\\\\ShellEx\\\\ContextMenuHandlers",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Classes\\\\*\\\\ShellEx\\\\PropertySheetHandlers",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Classes\\\\AllFileSystemObjects\\\\ShellEx\\\\ContextMenuHandlers",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Classes\\\\AllFileSystemObjects\\\\ShellEx\\\\DragDropHandlers",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Classes\\\\AllFileSystemObjects\\\\ShellEx\\\\PropertySheetHandlers",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Classes\\\\CLSID\\\\.*\\\\Instance",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Classes\\\\Directory\\\\Background\\\\ShellEx\\\\ContextMenuHandlers",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Classes\\\\Directory\\\\ShellEx\\\\ContextMenuHandlers",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Classes\\\\Directory\\\\Shellex\\\\CopyHookHandlers",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Classes\\\\Directory\\\\Shellex\\\\DragDropHandlers",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Classes\\\\Directory\\\\Shellex\\\\PropertySheetHandlers",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Classes\\\\Folder\\\\ShellEx\\\\ContextMenuHandlers",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Classes\\\\Folder\\\\ShellEx\\\\DragDropHandlers",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Classes\\\\Folder\\\\ShellEx\\\\ExtShellFolderViews",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Classes\\\\Folder\\\\ShellEx\\\\PropertySheetHandlers",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Classes\\\\Folder\\\\Shellex\\\\ColumnHandlers",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Active Setup\\\\Installed Components",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Command Processor\\\\Autorun",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Internet Explorer\\\\Explorer Bars",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Internet Explorer\\\\Extensions",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Internet Explorer\\\\Toolbar",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows CE Services\\\\AutoStartOnConnect",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows CE Services\\\\AutoStartOnDisconnect",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Drivers32",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\Appinit_Dlls",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Browser Helper Objects",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\SharedTaskScheduler",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\ShellExecuteHooks",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\ShellIconOverlayIdentifiers",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce",
            ".*\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\ShellServiceObjectDelayLoad",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\BootVerificationProgram\\\\ImagePath",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa\\\\Authentication Packages",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa\\\\Notification Packages",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa\\\\Security Packages",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\NetworkProvider\\\\Order",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Print\\\\Monitors",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\SafeBoot\\\\AlternateShell",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\SecurityProviders\\\\SecurityProviders",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session Manager\\\\AppCertDlls",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session Manager\\\\BootExecute",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session Manager\\\\Execute",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session Manager\\\\KnownDlls",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session Manager\\\\S0InitialCommand",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session Manager\\\\SetupExecute",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Terminal Server\\\\Wds\\\\rdpwd\\\\StartupPrograms",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Terminal Server\\\\WinStations\\\\RDP-Tcp\\\\InitialProgram",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Services",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\WinSock2\\\\Parameters\\\\NameSpace_Catalog5\\\\Catalog_Entries",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\WinSock2\\\\Parameters\\\\NameSpace_Catalog5\\\\Catalog_Entries64",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\WinSock2\\\\Parameters\\\\Protocol_Catalog9\\\\Catalog_Entries",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\WinSock2\\\\Parameters\\\\Protocol_Catalog9\\\\Catalog_Entries64"
        ]

	fileNames = [
            ".*\\\\win.ini",
            ".*\\\\system.ini",
            ".*\\\\Task Scheduler",
            ".*\\\\Start Menu\\\\Programs\\\\Startup"
        ]

        for file_name in results["behavior"]["summary"]["files"]:
            for indicator in fileNames:
                regexp = re.compile(indicator, re.IGNORECASE)
                if regexp.match(file_name):
                    self.data.append({"file_name" : file_name})
                    print(file_name + " matches " + indicator)
                    return True

        for regKey in results["behavior"]["summary"]["keys"]:
            for indicator in registryEntries:
                regexp = re.compile(indicator, re.IGNORECASE)
                if regexp.match(regKey):
                    self.data.append({"regKey" : regKey})
                    print(regKey + " matches " + indicator)
                    return True

        return False
