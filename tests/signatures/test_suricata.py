# Copyright (C) 2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from tests.utils import signature

def test_family_extraction():
    sig = signature("suricata_alert")(None)
    assert sig.extract_family("hello") is None
