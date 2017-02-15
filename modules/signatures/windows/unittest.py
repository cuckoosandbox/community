# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import requests

try:
    from cuckoo.common.abstracts import Signature
    from cuckoo.common.config import parse_options
except ImportError:
    class Signature(object):
        """For older Cuckoo setups, i.e., up to 2.0-rc2, we ignore the rest
        of this file by not inheriting from the real Signature class."""

def named_unittests(sig):
    ret, options = [], parse_options(
        sig.get_results("info", {}).get("options", "")
    )
    for unittest in options.get("unittest", "").split(":"):
        if not unittest.strip():
            continue

        ret.append("unittest.named.%s" % unittest.strip())
    return ret

class Unittest(Signature):
    severity = 5
    categories = ["unittest"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0.0"

    def on_complete(self):
        if named_unittests(self):
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
        finish = parse_options(options).get("unittest.finish", "")
        if not finish.isdigit() or not int(finish):
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
        self.unittests = named_unittests(self)

    def on_signature(self, signature):
        if signature.name in self.failure_signatures:
            self.failure = True

        # Little bit hacky, but aligns with NamedUnittest.
        if signature.name in self.unittests and signature.severity < 0:
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
        if self.name in named_unittests(self):
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

class ConnectLocal(object):
    filter_apinames = "connect",
    should_connect = None

    def check(self):
        connected = False
        for http in self.get_results("network", {}).get("http_ex", []):
            if http["host"] == "localhost":
                connected = True
        for http in self.get_results("network", {}).get("http", []):
            if http["host"] == "localhost":
                connected = True
        return self.should_connect == connected

class ResolveDns(object):
    should_resolve = None

    def check(self):
        for entry in self.get_results("network", {}).get("dns", []):
            if entry["request"] == "cuckoo.sh":
                return bool(entry["answers"]) == self.should_resolve

class RemoteDirect(object):
    filter_apinames = "connect",
    should_connect = None

    def check(self):
        connected = False
        for http in self.get_results("network", {}).get("http_ex", []):
            if http["host"] == "cuckoo.sh":
                connected = True
        for http in self.get_results("network", {}).get("http", []):
            if http["host"] == "cuckoo.sh":
                connected = True
        return self.should_connect == connected

class Myip(object):
    def ipaddr(self):
        for http in self.get_results("network", {}).get("http_ex", []):
            if http["host"] == "myip.cuckoo.sh":
                return open(http["resp"]["path"], "rb").read().strip()

class NormalRoutingUnittest(NamedUnittest):
    description = (
        "In default routing internal traffic is allowed and external "
        "traffic is not allowed."
    )

class DropRoutingUnittest(NamedUnittest):
    description = "In drop routing mode no traffic is allowed at all"

class InternetRoutingUnittest(NamedUnittest):
    description = "In internet routing mode dirty line traffic is allowed"

class TorRoutingUnittest(NamedUnittest):
    description = "In tor routing mode traffic is routed through Tor"

class NormalRoutingConnectLocal(ConnectLocal, NormalRoutingUnittest):
    name = "unittest.named.routing.normal.connect-local"
    should_connect = True

class DropRoutingConnectLocal(ConnectLocal, DropRoutingUnittest):
    name = "unittest.named.routing.drop.connect-local"
    should_connect = False

class InternetRoutingConnectLocal(ConnectLocal, InternetRoutingUnittest):
    name = "unittest.named.routing.internet.connect-local"
    should_connect = False

class TorRoutingConnectLocal(ConnectLocal, TorRoutingUnittest):
    name = "unittest.named.routing.tor.connect-local"
    should_connect = False

class NormalRoutingResolveDns(ResolveDns, NormalRoutingUnittest):
    name = "unittest.named.routing.normal.resolve-dns"
    should_resolve = False

class DropRoutingResolveDns(ResolveDns, DropRoutingUnittest):
    name = "unittest.named.routing.drop.resolve-dns"
    should_resolve = False

class InternetRoutingResolveDns(ResolveDns, InternetRoutingUnittest):
    name = "unittest.named.routing.internet.resolve-dns"
    should_resolve = True

class TorRoutingResolveDns(ResolveDns, TorRoutingUnittest):
    name = "unittest.named.routing.tor.resolve-dns"
    should_resolve = True

class NormalRoutingRemoteDirect(RemoteDirect, NormalRoutingUnittest):
    name = "unittest.named.routing.normal.remote-direct"
    should_connect = False

class DropRoutingRemoteDirect(RemoteDirect, DropRoutingUnittest):
    name = "unittest.named.routing.drop.remote-direct"
    should_connect = False

class InternetRoutingRemoteDirect(RemoteDirect, InternetRoutingUnittest):
    name = "unittest.named.routing.internet.remote-direct"
    should_connect = True

class TorRoutingRemoteDirect(RemoteDirect, TorRoutingUnittest):
    name = "unittest.named.routing.tor.remote-direct"
    should_connect = True

class NormalRoutingMyip(Myip, NormalRoutingUnittest):
    name = "unittest.named.routing.normal.myip"

    def check(self):
        return self.ipaddr() is None

class DropRoutingMyip(Myip, DropRoutingUnittest):
    name = "unittest.named.routing.drop.myip"

    def check(self):
        return self.ipaddr() is None

class InternetRoutingMyip(Myip, InternetRoutingUnittest):
    name = "unittest.named.routing.internet.myip"

    def check(self):
        ipaddr = requests.get("http://myip.cuckoo.sh/").content.strip()
        return self.ipaddr() == ipaddr

class TorRoutingMyip(Myip, TorRoutingUnittest):
    name = "unittest.named.routing.tor.myip"

    # Populated once.
    _ipaddrs = []

    def ipaddrs(self):
        if not self._ipaddrs:
            r = requests.get("https://check.torproject.org/exit-addresses")
            for line in r.content.split("\n"):
                if not line.startswith("ExitAddress"):
                    continue
                self._ipaddrs.append(line.split()[1])
        return self._ipaddrs

    def check(self):
        return self.ipaddr() in self.ipaddrs()
