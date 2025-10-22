from scapy.contrib.gtp import GTP_U_Header
from scapy.layers.inet import IP, ICMP, UDP
from scapy.all import Packet
from src.utils.protocols.pfcp.requests import PFCPRequest

def gtp_uplink_packet(src_addr:str, dst_addr:str, tunnel_dst_addr:str, ue_addr:str, teid:int, seq:int|None=None) -> Packet:

    gtp_message_template = "34ff005c0000000c0000008501100100"
    gtp_bytes = bytes.fromhex(gtp_message_template)
    gtp_message = GTP_U_Header(gtp_bytes)
    gtp_message.teid = teid

    if seq is None : 
        seq = PFCPRequest.random_seq()

    packet = (
        IP(src=src_addr, dst=dst_addr)
        / UDP(dport=2152, sport=2152)
        / gtp_message
        / IP(src=ue_addr, dst=tunnel_dst_addr)
        / ICMP(type=8, id=0x1234, seq=seq)
    )

    return packet
