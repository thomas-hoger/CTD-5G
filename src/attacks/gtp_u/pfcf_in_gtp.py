from scapy.layers.inet import IP, UDP
from scapy.contrib.gtp import GTP_U_Header
from scapy.all import Packet

from src.utils.protocols.pfcp.requests_from_scratch import PFCPRequest

def pfcp_in_gtp_packet(src_addr:str, dst_addr:str, teid:int, pfcp_packet: Packet) -> Packet:
        
    # gtp_message_template = "34ff005c000000020000008501100000"
    gtp_message_template = "34ff005c0000000c0000008501100100"
    gtp_bytes = bytes.fromhex(gtp_message_template)
    gtp_message = GTP_U_Header(gtp_bytes)
    gtp_message.teid = teid
        
    pfcp_content = PFCPRequest.association_setup(src_addr, dst_addr)
        
    gtp_packet = (
        IP(src=src_addr, dst=dst_addr)
        / UDP(sport=2152, dport=2152)
        / gtp_message
        / pfcp_content
    )
        
    return gtp_packet
