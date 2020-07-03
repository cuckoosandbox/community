# Copyright (C) 2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

import cuckoo

from cuckoo.misc import load_signatures, decide_cwd

def signature(name):
    for signature in cuckoo.signatures:
        if signature.name == name or signature.__class__.__name__ == name:
            return signature

# For reasons.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

# Initialize a fake CWD and actually load all Cuckoo Signature, once.
# TODO Create a temporary CWD with a symbolic link to our $CWD/signatures/.
decide_cwd(os.path.join(os.path.dirname(__file__), "..", "modules"))
load_signatures()
