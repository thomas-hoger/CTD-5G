from __future__ import annotations

from src.utils.protocols.pfcp.requests import PFCPRequest
from src.utils.common import get_my_ip_from_prefix, ip_list

from scapy.all import send
import time

def test_establish():
    
    # Send association setup 
    packet = PFCPRequest.association_setup(
        src_addr = get_my_ip_from_prefix(), 
        dst_addr = ip_list["UPF"])
    send(packet) 
    
    time.sleep(5)
    
    # Etablishment request
    send(
        PFCPRequest.session_establishment(
            src_addr=get_my_ip_from_prefix(),
            dst_addr=ip_list["UPF"],
            ue_addr=PFCPRequest.random_ue_address(),
            teid=1,
            seid=1
        )
    )