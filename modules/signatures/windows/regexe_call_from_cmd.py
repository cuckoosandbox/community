# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class RegCallfromCMD(Signature):

    name = "reg_called_from_cmd"
    description = "Reg.exe called from Command Shell"
    severity = 3
    categories = ["analytic"]
    authors = ["ZW"]
    minimum = "2.0"
    reference = ["https://car.mitre.org/analytics/CAR-2013-03-001/"]
    ttp = [""]

    def on_complete(self):
      
      for process in self.get_results("behavior", {}).get("processtree", []):
            stack = [process]     
            traversed_path = []
            
            while stack:
                process_visit = stack.pop()
                
                if process_visit["process_name"] == "reg.exe":
                    for visited_process_find_parent in traversed_path:
                        if process_visit["ppid"] == visited_process_find_parent["pid"] and visited_process_find_parent["process_name"] == "cmd.exe":
                            for visited_process_find_GP in traversed_path:
                                if visited_process_find_parent["ppid"] == visited_process_find_GP["pid"] and visited_process_find_GP["process_name"] != "explorer.exe":
                                    self.mark(marked_process = process)
                                   
                                    return self.has_marks()
                                                
                traversed_path.append(process_visit)
                stack.extend(process_visit['children']) 
                

      