from scapy.contrib.gtp import GTP_U_Header
from scapy.layers.inet import IP, ICMP, UDP
from scapy.all import Packet
from src.utils.protocols.pfcp.pfcp import PFCPRequest

def gtp_uplink_packet(src_addr:str, dst_addr:str, tunnel_dst_addr:str, ue_addr:str, teid:int, seq:int=PFCPRequest.random_seq()) -> Packet:

    packet = (
        IP(src=src_addr, dst=dst_addr)
        / UDP(dport=2152, sport=2152)
        / GTP_U_Header(teid=teid)
        / IP(src=ue_addr, dst=tunnel_dst_addr)
        / ICMP(type=8, id=0x1234, seq=seq)
    )

    return packet
