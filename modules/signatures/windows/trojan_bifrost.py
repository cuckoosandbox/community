from lib.cuckoo.common.abstracts import Signature

class BifrostTrojan(Signature):
    # This signature is intended to catch references to the HKEY_LOCAL_MACHINE\SOFTWARE\Bifrost registry key, based on observations of a sample.
    # It may be too specific to be widely applicable, and could potentially be extended to catch references in direct registry operations. However
    # the malware sample observed did not reach the stage of execution which actually made changes to the registry, but sections of the path could be
    # observed in buffers injected into explorer.exe.
    name = "trojan_bifrost"
    description = "Includes registry keys related to the Bifrost Trojan backdoor"
    severity = 5
    categories = ["trojan"]
    authors = ["Brae"]
    minimum = "2.0"

    filter_apinames = [
        "NtWriteVirtualmemory",
        "WriteProcessMemory",
    ]

    process_handles = ["0xffffffff", "0xffffffffffffffff"]

    def on_call(self, call, process):
        proc_handle = call["arguments"]["process_handle"]

        if len(call["arguments"]["buffer"]) > 0 and proc_handle not in self.process_handles:
            injected_pid = call["arguments"]["process_identifier"]
            call_process = self.get_process_by_pid(injected_pid)

            if not call_process or call_process["ppid"] != process["pid"]:
                if "SOFTWARE\Bifrost" in call["arguments"]["buffer"]:
                    self.mark_config({
                        "family":"Bifrost Trojan",
                        "url":"https://www.symantec.com/connect/blogs/retrospective-tour-backdoorbifrose",
                        "type":"Contains references to registry keys associated with the Bifrost remote access trojan"
                    })


    def on_complete(self):
        return self.has_marks()
