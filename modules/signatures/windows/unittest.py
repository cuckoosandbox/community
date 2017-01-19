# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

try:
    from cuckoo.common.abstracts import Signature
    from cuckoo.common.config import parse_options
except ImportError:
    class Signature(object):
        """For older Cuckoo setups, i.e., up to 2.0-rc2, we ignore the rest
        of this file by not inheriting from the real Signature class."""

class Unittest(Signature):
    severity = 5
    categories = ["unittest"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0.0"

    def on_complete(self):
        options = self.get_results("info", {}).get("options", "")
        options = parse_options(options)
        if options.get("unittest"):
            return self.check()

    def check(self):
        pass

class UnittestAssert(Unittest):
    name = "unittest.assert"
    description = "This unittest failed one or more assert statements"

    def check(self):
        for line in self.get_results("debug", {}).get("log", []):
            if "CRITICAL:" in line and "Test didn't" in line:
                self.mark(line=line)
        return self.has_marks()

class UnittestError(Unittest):
    name = "unittest.error"
    description = "This unittest threw one or more errors"

    def check(self):
        for line in self.get_results("debug", {}).get("log", []):
            if "CRITICAL:" in line:
                self.mark(line=line)
        return self.has_marks()

class UnittestWarning(Unittest):
    name = "unittest.warning"
    description = "This unittest threw one or more warnings"

    def check(self):
        for line in self.get_results("debug", {}).get("log", []):
            if "WARNING:" in line:
                self.mark(line=line)
        return self.has_marks()

class UnittestNoFinish(Unittest):
    name = "unittest.nofinish"
    description = "This unittest doesn't indicate it has finished"

    def check(self):
        options = self.get_results("info", {}).get("options", "")
        options = parse_options(options)
        if not int(options.get("unittest.finish")):
            return

        for line in self.get_results("debug", {}).get("log", []):
            if "Test finished!" in line:
                return False
        return True

class UnittestAnswer(Unittest):
    # The name will be changed at runtime but is required for initialization.
    name = "unittest.answer"
    # The order should be higher than any other unittest-related Signature.
    order = 3

    failure_signatures = [
        "unittest.assert", "unittest.error",
        "unittest.warning", "unittest.nofinish",
    ]

    def init(self):
        self.failure = False

        options = self.get_results("info", {}).get("options", "")
        options = parse_options(options)
        self.unittest = "unittest.named.%s" % options.get("unittest")

    def on_signature(self, signature):
        if signature.name in self.failure_signatures:
            self.failure = True

        # Little bit hacky, but aligns with NamedUnittest.
        if signature.name == self.unittest and signature.severity < 0:
            self.failure = True

    def on_complete(self):
        if self.failure:
            self.name = "unittest.failure"
            self.description = "This unittest failed to succeed"
        else:
            self.name = "unittest.success"
            self.description = "This unittest ran successfully"
        return True

class NamedUnittest(Signature):
    severity = 5
    categories = ["unittest"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0.0"

    def on_complete(self):
        options = self.get_results("info", {}).get("options", "")
        options = parse_options(options)
        unittest = "unittest.named.%s" % options.get("unittest")
        if unittest == self.name:
            # Little bit hacky, but aligns with UnittestAnswer.
            if self.check() is True:
                self.severity = 5
            else:
                self.severity = -5
            return True

    def check(self):
        """Function to identify whether the signature has been successful.
        Returns True upon success and anything else upon failure."""

class BreakpipeUnittest(NamedUnittest):
    name = "unittest.named.breakpipe"
    description = "Program intentionally breaking the monitor pipe handle"

    def check(self):
        apistats = self.get_results("behavior", {}).get("apistats", {})
        count = 0
        for funcs in apistats.values():
            count += funcs.get("MessageBoxTimeoutA", 0)
        return count == 2
