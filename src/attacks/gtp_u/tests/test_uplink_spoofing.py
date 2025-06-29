from __future__ import annotations

from src.utils.ueransim.ue import UserEquipment 
from src.attacks.gtp_u.uplink_spoofing import gtp_uplink_packet
from src.utils.common import get_my_ip_from_prefix, ip_list

import pytest
from scapy.all import send

@pytest.fixture(autouse=True)
def clear_ues():
    
    # Setup
    UserEquipment.terminate_all()
    
    # Execution
    yield 
    
    # Teardown 
    UserEquipment.terminate_all()
    
def test_spoofing():
    
    # Create new UE
    test_imsi = UserEquipment.get_available_imsi() # Get a random IMSI that is not currently registered
    test_ue:UserEquipment|None = UserEquipment.register_new(test_imsi)
    session = test_ue.sessions[0]
    
    # Send gtp uplink packet
    packet = gtp_uplink_packet(
        src_addr = get_my_ip_from_prefix(), 
        dst_addr = ip_list["UPF"],
        tunnel_dst_addr = "8.8.8.8", # random address from internet
        ue_addr = session.address,
        teid = session.teid
    )
    send(packet)
    
    # by sniffing the network we should see a response that is directed to the UE IP address