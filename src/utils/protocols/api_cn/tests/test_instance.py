from __future__ import annotations

from src.utils.ueransim.ue import UserEquipment 
from src.utils.protocols.api_cn.instance import NFInstance, NF_PARAMETER_FOLDER

import pytest
import json

@pytest.fixture(autouse=True)
def clear_ues():
    
    # Setup
    UserEquipment.terminate_all()
    
    # Execution
    yield 
    
    # Teardown 
    UserEquipment.terminate_all()
    

def test_interact():

    # Ping NRF
    assert NFInstance.ping_nf("NRF", display=False)
    
    # Check parameter import
    nf_type    = NFInstance.get_random_nf_type()
    assert nf_type
    
    with open(f"{NF_PARAMETER_FOLDER}/{nf_type}.json") as f:
        parameters = json.load(f)
    assert len(parameters.keys()) > 0

    # Add instance
    instance:NFInstance|None = NFInstance.add_random_nf(display=False)
    NFInstance.nf_list.append(instance) 
    assert instance

    # Create token
    token = instance.get_token("nnrf-disc", "NRF", display=False)
    assert token

    # Find a UDM instance
    infos = instance.get_nf_info(token, "UDM", display=False)
    assert infos

    # Remove instance
    removed = instance.remove_nf(token, display=False)
    NFInstance.nf_list.remove(instance) 
    assert removed
