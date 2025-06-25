from scapy.contrib.gtp import GTP_U_Header
from scapy.layers.inet import IP, ICMP, UDP
import random

from src.utils.common import ip_list

def new_seq(rand=False):
    return random.randint(0, 0xFFFF)

def gtp_uplink_packet(src_addr:str, dest_addr:str, teid:int, ue_addr:str):

    packet = (
        IP(src=src_addr, dst=ip_list["UPF"])
        / UDP(dport=2152, sport=2152)
        / GTP_U_Header(teid=teid)
        / IP(src=ue_addr, dst=dest_addr)
        / ICMP(type=8, id=0x1234, seq=new_seq(True))
    )

    return packet
