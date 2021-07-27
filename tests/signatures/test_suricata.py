# Copyright (C) 2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from tests.utils import signature

def test_family_extraction():
    sig = signature("suricata_alert")(None)
    assert sig.extract_family("hello") is None
    assert sig.extract_family(
        "ET TROJAN LokiBot Related DNS query"
    ) == "loki"

    assert sig.extract_family(
        "ET TROJAN Loki Bot Request for C2 Commands Detected M1"
    ) == "loki"

    assert sig.extract_family(
        "ET TROJAN Loki Bot Application/Credential Data Exfiltration Detected M2"
    ) == "loki"

    assert sig.extract_family(
        "ET TROJAN IoT_reaper DNS Lookup M7"
    ) == "iot_reaper"

    assert sig.extract_family(
        "ET TROJAN Banker.ili HTTP Checkin"
    ) == "banker"

    assert sig.extract_family(
        "ET TROJAN Klom.A Connecting to Controller"
    ) == "klom"

    assert sig.extract_family(
        "ET TROJAN W32/SPARS/ARS Stealer Checkin"
    ) == "spars"

    assert sig.extract_family(
        "ET TROJAN Backdoor.Elise CnC Beacon 2 M2"
    ) == "elise"

    assert sig.extract_family(
        "ET TROJAN [Flashpoint] Possible CVE-2018-4878 Check-in"
    ) is None

    assert sig.extract_family(
        "ET TROJAN Observed Evrial Domain (cryptoclipper .ru in DNS Lookup)"
    ) is None

    assert sig.extract_family(
        "ET TROJAN WooSIP Downloader CnC DeleteFileOnServer"
    ) == 'woosip'

    assert sig.extract_family(
        "ET TROJAN Possible Trickbot/Dyre Serial Number in SSL Cert"
    ) is None

    assert sig.extract_family(
        "ET TROJAN [PTsecurity] DorkBot.Downloader CnC Response"
    ) == "dorkbot"

    assert sig.extract_family(
        "ET TROJAN MSIL/Unk.Stealer Data Exfil Via HTTP"
    ) is None

    assert sig.extract_family(
        "ET TROJAN ABUSE.CH SSL Blacklist Malicious SSL certificate detected (Vawtrak CnC)"
    ) is None

    assert sig.extract_family(
        "ET TROJAN W32/TrojanSpy.MSIL Fetch Time CnC Beacon"
    ) == "trojanspy"

    assert sig.extract_family(
        "ET TROJAN - Possible Zeus/Perkesh (.bin) configuration download"
    ) is None

