from __future__ import annotations

from src.utils.ueransim.ue import UserEquipment 
from src.utils.protocols.pfcp.requests import PFCPRequest
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
    
def test_delete():
    
    # Create new UE
    test_imsi = UserEquipment.get_available_imsi() # Get a random IMSI that is not currently registered
    test_ue:UserEquipment|None = UserEquipment.register_new(test_imsi)
    session = test_ue.sessions[0]
   
    # New UE should be able to ping
    assert session.uplink_traffic()

    # Send session deletion packet
    packet = PFCPRequest.session_deletion(
        src_addr = get_my_ip_from_prefix(),
        dst_addr = ip_list["UPF"],
        seid = session.seid,
    )
    send(packet)
        
    # New UE should not be able to ping
    assert not session.uplink_traffic()
    test_ue.deregister()
