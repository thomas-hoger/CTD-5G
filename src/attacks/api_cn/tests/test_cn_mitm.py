import httpx
import json
import urllib
import pytest
import os 

from src.attacks.api_cn.cn_mitm import CNMitm
from src.utils.common import ip_list

@pytest.fixture(autouse=True)
def clear_ues():
    
    # Setup
    os.popen("pkill -f socat")
    
    # Execution
    yield 


def test_manipulation():
    
    nf_to_spoof = "UDR"
    assert CNMitm.start(nf_to_spoof)
    
    # Verify that the mitm is registered
    infos = CNMitm.attacker_instance.get_nf_info("", nf_to_spoof)
    assert infos 
    assert "nfInstances" in infos 
    assert len(infos["nfInstances"]) == 1
    
    # Verify that the mitm is the oldest (= top priority NF)
    registered_nf = infos["nfInstances"][0]
    assert CNMitm.mitm_instance.nf_instance_id == registered_nf["nfInstanceId"]
    
    # Send legitimate UDM request
    # With this request, the UDM is supposed to ask the UDR (which is now our mitm)
    # If we have a response the mitm is well established
    # It can be further verified with wireshark 
    # The sequence is supposed to be :
    #   MITM (fake legitimate) -> UDM 
    #   UDM -> MITM (fake UDR)
    #   MITM (fake UDR) -> UDR
    #   UDR -> MITM (fake UDR)
    #   MITM (fake UDR) -> UDM 
    #   UDM -> MITM (fake legitimate)
    ip   = f"http://{ip_list["UDM"]}:8080/"  # MITM iP
    supi = "208950000000031"
    url  = ip + f"nudm-ueau/v1/{supi}/security-information/generate-auth-data"
    data = {
        "ausfInstanceId": "400346f4-087e-40b1-a4cd-00566953999d",
        "servingNetworkName": "5G:mnc095.mcc208.3gppnetwork.org"
}
    
    # Basic headers
    headers = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Connection": "keep-alive",
        "Content-Type": "application/json",
    }

    # Send the request to the target server
    with httpx.Client(http1=False, http2=True, verify=False) as client:
        response = client.request("POST", url, data=json.dumps(data), headers=headers)
        
    print(response)
        
    # Check if request worked
    assert 200 <= response.status_code < 300
    
    # Stop the mitm 
    assert CNMitm.stop() 
    
    # Verify that the mitm is deregistered
    infos = CNMitm.attacker_instance.get_nf_info("", nf_to_spoof)
    assert infos 
    assert "nfInstances" in infos 
    assert len(infos["nfInstances"]) >= 1
    
    # Verify that the mitm is the oldest (= top priority NF)
    oldest_nf = infos["nfInstances"][0]
    assert CNMitm.mitm_instance.nf_instance_id != oldest_nf["nfInstanceId"]