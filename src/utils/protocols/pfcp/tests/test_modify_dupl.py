from __future__ import annotations

from src.utils.protocols.pfcp.requests import PFCPRequest
from src.utils.common import get_my_ip_from_prefix, ip_list

from scapy.all import send
import time
    
def test_modify_dupl():
    
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

    # Send modification packet
    packet = PFCPRequest.session_modification(
        src_addr = get_my_ip_from_prefix(),
        dst_addr = ip_list["UPF"],
        ue_addr = "10.60.36.239", # have to adjust to upf log
        seid = 3, # have to adjust to upf log
        teid = 1,
        far_id = 1,
        actions = ["FORW","DUPL"]
    )
    
    # We should observe that the packet is sent 2 times in 
    send(packet)