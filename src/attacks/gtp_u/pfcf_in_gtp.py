from scapy.layers.inet import IP, UDP
from scapy.contrib.gtp import GTP_U_Header
from scapy.all import Packet

def pfcp_in_gtp_packet(src_addr:str, dst_addr:str, teid:int, pfcp_packet: Packet) -> Packet:
    
    gtp_packet = (
        IP(src=src_addr, dst=dst_addr)
        / UDP(sport=2152, dport=2152)
        / GTP_U_Header(teid=teid)
        / pfcp_packet
    )
    return gtp_packet
