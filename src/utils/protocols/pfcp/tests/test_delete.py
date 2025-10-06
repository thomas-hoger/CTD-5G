from __future__ import annotations

from src.utils.protocols.pfcp.requests import PFCPRequest
from src.utils.common import get_my_ip_from_prefix, ip_list

from scapy.all import send
import time
    
def test_delete():
    
    # Create new UE
    # packet = PFCPRequest.association_setup(
    #     src_addr = get_my_ip_from_prefix(), 
    #     dst_addr = ip_list["UPF"])
    # send(packet) 
    
    # time.sleep(2)
    
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
    
    time.sleep(2)

    # Send session deletion packet
    packet = PFCPRequest.session_deletion(
        src_addr = get_my_ip_from_prefix(),
        dst_addr = ip_list["UPF"],
        seid = 2,  # have to adjust to upf log
    )
    send(packet)
