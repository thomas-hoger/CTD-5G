from __future__ import annotations

from src.utils.ueransim.ue import UserEquipment 
from src.utils.protocols.pfcp.requests import PFCPRequest
from src.utils.ueransim.session import PDUSession 
from src.utils.common import get_my_ip_from_prefix, ip_list

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
    
def test_modify_dupl():
    
    test_imsi = UserEquipment.get_available_imsi() # Get a random IMSI that is not currently registered
    test_ue:UserEquipment|None = UserEquipment.register_new(test_imsi)
    assert test_ue
    
    session = test_ue.sessions[0]
    assert session
    
    # New UE can ping
    assert session.uplink_traffic()
    
    possible_far_ids = PDUSession.get_far_id_by_seid(session.seid)
    assert possible_far_ids

    # Send modification packet
    packet = PFCPRequest.session_modification(
        src_addr = get_my_ip_from_prefix(),
        dst_addr = ip_list["UPF"],
        ue_addr = session.address,
        seid = session.seid,
        teid = session.teid,
        far_id = random.choice(possible_far_ids),
        actions = ["FORW","DUPL"]
    )
    
    # We should observe that the packet is sent 2 times in 
    send(packet)