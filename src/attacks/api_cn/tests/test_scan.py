from __future__ import annotations

from src.utils.protocols.api_cn.instance import NFInstance

def test_interact():

    # Add instance
    instance:NFInstance|None = NFInstance.add_random_nf(nf_type="UDM",display=False)
    NFInstance.nf_list.append(instance) 
    assert instance

    # Create token
    token = instance.get_token("nnrf-disc", "NRF")
    assert token

    # Find a UDM instance
    for nf_type in ["UDM","UDR","AMF"]:
        infos = instance.get_nf_info(token, nf_type)
        assert len(infos["nfInstances"]) > 0
        
    # Remove instance
    removed = instance.remove_nf(token)
    NFInstance.nf_list.remove(instance) 
    assert removed