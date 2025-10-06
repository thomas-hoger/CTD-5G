from __future__ import annotations

from src.utils.protocols.pfcp.requests import PFCPRequest
from src.utils.common import get_my_ip_from_prefix, ip_list

from scapy.all import send

def test_establish():
        
    # Etablishment request
    send(
        PFCPRequest.session_establishment(
            smf_addr=get_my_ip_from_prefix(),
            upf_addr=ip_list["UPF"],
            ue_addr=PFCPRequest.random_ue_address(),
            teid=1,
            seid=1
        )
    )