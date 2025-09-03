from __future__ import annotations

from src.utils.protocols.api_cn.instance import NFInstance

def test_interact():

    # Add instance
    instance:NFInstance|None = NFInstance.add_random_nf(nf_type="UDM",display=False)
    NFInstance.nf_list.append(instance) 
    assert instance

    # Find a UDM instance
    for nf_type in ["UDM","UDR","AMF"]:
        infos = instance.get_nf_info("", nf_type)
        assert len(infos["nfInstances"]) > 0
        
    # Remove instance
    removed = instance.remove_nf("")
    NFInstance.nf_list.remove(instance) 
    assert removed