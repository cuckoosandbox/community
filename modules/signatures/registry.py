from lib.cuckoo.common.abstracts import Signature

from common.win32api import detect

class Registry(Signature):
    name = "search_registry"
    description = "Process that reads or writes to the registry."
    severity = 1
    authors = ["Matthew Bradbury <matt-bradbury(at)live(dot)co(dot)uk>"]
    category = ["API Search"]

    references = ["http://msdn.microsoft.com/en-us/library/windows/desktop/ms724875%28v=vs.85%29.aspx"]

    apis = {"GetPrivateProfileInt", "GetPrivateProfileSection", "GetPrivateProfileSectionNames", 
            "GetPrivateProfileString", "GetPrivateProfileStruct", "GetProfileInt", 
            "GetProfileSection", "GetProfileString", "RegCloseKey", "RegConnectRegistry", 
            "RegCopyTree", "RegCreateKey", "RegCreateKeyEx", "RegCreateKeyTransacted", 
            "RegDeleteKey", "RegDeleteKeyEx", "RegDeleteKeyTransacted", "RegDeleteKeyValue", 
            "RegDeleteTree", "RegDeleteValue", "RegDisablePredefinedCache", "RegDisablePredefinedCacheEx", 
            "RegDisableReflectionKey", "RegEnableReflectionKey", "RegEnumKey", "RegEnumKeyEx", 
            "RegEnumValue", "RegFlushKey", "RegGetValue", "RegLoadAppKey", "RegLoadKey", 
            "RegLoadMUIString", "RegNotifyChangeKeyValue", "RegOpenCurrentUser", "RegOpenKey", 
            "RegOpenKeyEx", "RegOpenKeyTransacted", "RegOpenUserClassesRoot", "RegOverridePredefKey", 
            "RegQueryInfoKey", "RegQueryMultipleValues", "RegQueryReflectionKey", "RegQueryValue", 
            "RegQueryValueEx", "RegReplaceKey", "RegRestoreKey", "RegSaveKey", "RegSaveKeyEx", 
            "RegSetKeyValue", "RegSetValue", "RegSetValueEx", "RegUnLoadKey", "WritePrivateProfileSection", 
            "WritePrivateProfileString", "WritePrivateProfileStruct", "WriteProfileSection",
            "WriteProfileString"
           }

    def run(self, results):
        return detect(self, results)
        



