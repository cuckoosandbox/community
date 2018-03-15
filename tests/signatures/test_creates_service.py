# Copyright (C) 2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from tests.utils import signature

def test_creates_service():
    sig = signature("creates_service")(None)
    sig.on_call({
        "api": "CreateServiceW",
        "arguments": {
            "service_name": None,
        }
    }, None)
