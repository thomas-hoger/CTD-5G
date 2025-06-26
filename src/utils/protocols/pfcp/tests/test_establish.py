from __future__ import annotations

from src.utils.protocols.pfcp.pfcp import PFCPRequest
from src.utils.common import get_my_ip_from_prefix, ip_list

from scapy.all import send

def test_establish():
    
    # Send association setup 
    # I tried to assert the functionning by listening the response 
    # But sr1 and sniff don't capture the trafic even if I can see it in wireshark
    packet = PFCPRequest.association_setup(
        src_addr = get_my_ip_from_prefix(), 
        dst_addr = ip_list["UPF"])
    send(packet) 