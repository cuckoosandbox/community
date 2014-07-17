# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class SystemMetrics(Signature):
    name = "antidbg_api"
    description = "Uses Anti Debugging Techniques"
    severity = 3
    categories = ["anti-debug"]
    authors = ["Sergio Galan aka @NaxoneZ"]
    minimum = "0.5"
    evented = True

    def on_call(self, call, process):
	  if call["api"].startswith("IsDebuggerPresent"):
      return True

	  if call["api"].startswith("IsDebugger"):
      return True

    if call["api"].startswith("NtQueryInformationProcess"):
      return True

    if call["api"].startswith("CheckRemoteDebuggerPresent"):
      return True

    if call["api"].startswith("SetInformationThread"):
      return True

    if call["api"].startswith("DebugActiveProcess"):
      return True

    if call["api"].startswith("QueryPerformanceCounter"):
      return True

    if call["api"].startswith("GetTickCount"):
      return True

    if call["api"].startswith("OutputDebugString"):
      return True

    if call["api"].startswith("SetUnhandledExceptionFilter"):
      return True

    if call["api"].startswith("GenerateConsoleCtrlEvent"):
      return True

    if call["api"].startswith("SetConsoleCtrlHandler"):
      return True

    if call["api"].startswith("SetThreadContext"):
      return True

    if call["api"].startswith("AddVectoredExceptionHandler"):
      return True

    if call["api"].startswith("RemoveVectoredExceptionHandler"):
      return True

    if call["api"].startswith("RemoveVectoredExceptionHandler"):
      return True
