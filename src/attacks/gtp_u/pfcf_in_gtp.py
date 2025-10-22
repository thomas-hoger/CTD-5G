from scapy.layers.inet import IP, UDP
from scapy.contrib.gtp import GTP_U_Header
from scapy.all import Packet

def pfcp_in_gtp_packet(src_addr:str, dst_addr:str, teid:int, pfcp_packet: Packet) -> Packet:
    
    gtp_message_template = "34ff005c0000000c0000008501100100"
    gtp_bytes = bytes.fromhex(gtp_message_template)
    gtp_message = GTP_U_Header(gtp_bytes)
    gtp_message.teid = teid
    
    gtp_packet = (
        IP(src=src_addr, dst=dst_addr)
        / UDP(sport=2152, dport=2152)
        / gtp_message
        / pfcp_packet
    )
    return gtp_packet
