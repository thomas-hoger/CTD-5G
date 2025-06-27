from __future__ import annotations

import httpx
import urllib.parse
import random
import json
import os

from src.utils.common import ip_list, generate_variables

NF_PARAMETER_FOLDER = "./src/utils/protocols/api_cn/new_nf_parameters/free5gc"

class NFInstance:
    
    nf_type_list = [
        "UDM",
        "AMF",
        "SMF",
        "AUSF",
        "PCF",
        "UDR",
        "NSSF",
        "CHF",
        "NEF",
    ]
    
    nf_list = []
    
    def __init__(self, nf_instance_id:str , nf_type:str , ip_address:str , services: list[str]):
        self.nf_instance_id = nf_instance_id
        self.nf_type = nf_type
        self.ip_address = ip_address
        self.services = services
        self.token = ""

    # COMMON 

    def request_cn(nf_type: str, data:dict, method:str, uri:str, headers={}, token="", display=True):
        """
        Sends an HTTP request to a specified core network (CN) NF instance.

        Args:
            nf_type (str): The network function instance to target.
            data (dict): Data to send in the request (query params, body, or JSON).
            method (str): HTTP method (e.g., 'GET', 'POST', 'DELETE').
            uri (str): URI path for the request.
            headers (dict, optional): Additional HTTP headers. Defaults to {}.
            token (str, optional): Bearer token for Authorization header. Defaults to "".
            display (bool, optional): If True, prints request and response details. Defaults to True.

        Returns:
            tuple: (status_code, response content as dict or str)
        """

        url = f"http://{ip_list[nf_type.upper()]}:8000" + uri

        base_headers = {
            # "Content-Type": "application/json", # géré tout seul par .post .get et le fait de mettre data= ou json=
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Authorization": f"Bearer {token}",  # Ajout de l'en-tête d'autorisation
        }

        base_headers.update(headers)
        method = method.upper()

        with httpx.Client(http1=False, http2=True, verify=False) as client:

            if method in ["GET", "DELETE"]:
                if data:
                    query_string = urllib.parse.urlencode(data, doseq=True)
                    url += f"?{query_string}"
                response = client.request(method, url, headers=base_headers)
            elif method == "POST":
                response = client.request(method, url, data=data, headers=base_headers)
            else:
                response = client.request(method, url, json=data, headers=base_headers)

        try:
            result = response.json()
        except Exception:
            result = response.text

        if display:
            print(f"Request {method} {url}")
            if headers:
                print(f"-> Headers : {headers}")
            if data:
                print(f"-> Body : {data}")
            print(f"-> Status Code {response.status_code}")
            print(result)

        return response.status_code, result
    
    def ping_nf(instance: NFInstance, display=True) -> bool:
        status, _ = NFInstance.request_cn(instance, {}, "GET", "", display=display)
        return 200 <= status < 300 
    
    def get_available_ip_list() -> list[str]:
        """
        Generates and returns an available IP address in the format '10.100.200.X', 
        where X is not currently assigned to any CN component or temporary NF instance.
        """
        
        available_ips = [f"10.100.200.{i}" for i in range(1,256)]  
        available_ips = [ip for ip in available_ips if ip not in ip_list.values()] # Avoid IPs already used by CN components
        
        addresses_used_by_temporary_nf = [nf.ip_address for nf in NFInstance.nf_list]
        available_ips = [ip for ip in available_ips if ip not in addresses_used_by_temporary_nf] # Avoid IPs already used by temporary NFs
        
        return available_ips 

    def get_random_nf_type() -> str:
        nf_types   = [os.path.splitext(f)[0] for f in os.listdir(NF_PARAMETER_FOLDER) if ".json" in f]
        return random.choice(nf_types).upper()
    
    # NRF REQUESTS 

    def add_nf(nf_instance_id:str, nf_type:str, nf_services:list[str]=[], ip_address="", additionnal_data={}, display=True) -> NFInstance | None :
        """
        Adds a Network Function (NF) instance to the system, optionally specifying its type, services, IP address, and additional data.
        Args:
            nf_instance_id (str): Unique identifier for the NF instance.
            nf_type (str): Type of the NF instance.
            nf_services (list[str], optional): List of NF service names to register. Defaults to [].
            ip_address (str, optional): Specific IP address to assign. If not provided, a random available IP is used. Defaults to "".
            additionnal_data (dict, optional): Additional fields to include in the NF instance data. Defaults to {}.
            display (bool, optional): Whether to display request information. Defaults to True.
        Returns:
            NFInstance | None: The created NFInstance object if successful, otherwise None.
        """

        available_ip_list = NFInstance.get_available_ip_list()
        
        if not ip_address :
            ip_address = random.choice(available_ip_list)
            
        # Required values
        data = {
            "nfInstanceId": nf_instance_id,
            "nfType": nf_type,
            "nfStatus": "REGISTERED",
            "ipv4Addresses": [ip_address]
        }
        
        # Optionnal values
        data = {**data, **additionnal_data}

        # Sugar coating to add services with only their name
        if nf_services :
            if "nfServices" not in data.keys() :
                data["nfServices"] = []
            
            for i, nf_service in enumerate(nf_services):
                data["nfServices"].append(
                    {
                        "serviceInstanceId": str(i),
                        "serviceName": nf_service,
                        "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.3"}],
                        "scheme": "http",
                        "nfServiceStatus": "REGISTERED",
                        "ipEndPoints": [
                            {"ipv4Address": ip_address, "transport": "TCP", "port": 8000}
                        ],
                        "apiPrefix": f"http://{ip_address}:8000",
                    }
                )

        status, _ = NFInstance.request_cn("NRF", data, "PUT", f"/nnrf-nfm/v1/nf-instances/{nf_instance_id}", display=display)

        if 200 <= status < 300 :
            instance = NFInstance(nf_instance_id, nf_type, ip_address, nf_services)
            return instance

    def add_random_nf(nf_instance_id:str=generate_variables("uuid"), nf_type="", display=True) -> NFInstance | None :
        """
        Adds a randomly generated legitimate Network Function (NF) instance with random parameters and IP address.
        Args:
            nf_instance_id (str): Unique identifier for the NF instance. Defaults to a generated UUID.
            display (bool, optional): Whether to display request information. Defaults to True.
        Returns:
            NFInstance | None: The created NFInstance object if successful, otherwise None.
        """
        
        if not nf_type :
            nf_type = NFInstance.get_random_nf_type()
        ip_address = random.choice(NFInstance.get_available_ip_list())
        
        with open(f"{NF_PARAMETER_FOLDER}/{nf_type.lower()}.json") as f:
            parameters = json.load(f)

        return NFInstance.add_nf(nf_instance_id, nf_type.upper(), ip_address=ip_address, additionnal_data=parameters, display=display)

    def remove_nf(instance: NFInstance, token: str, display=True) -> bool:
        """Remove a Network Function (NF) instance from the system."""
        uri = f"/nnrf-nfm/v1/nf-instances/{instance.nf_instance_id}"
        status, _ = NFInstance.request_cn("NRF", {}, "DELETE", uri, token=token, display=display)
        return 200 <= status < 300 

    def get_token(instance: NFInstance, scope="nnrf-disc", target_type="NRF", additionnal_data={}, display=True) -> str | None:
        """
        Retrieve an access token for a given NFInstance using client credentials.

        Args:
            instance (NFInstance): The network function instance requesting the token.
            scope (str): The scope of the requested token.
            target_type (str): The target network function type.
            additionnal_data (dict, optional): Additional data to include in the request. Defaults to {}.
            display (bool, optional): Whether to display request information. Defaults to True.

        Returns:
            str | None: The access token if the request is successful, otherwise None.
        """
        
        data = {
            "grant_type": "client_credentials",
            "nfInstanceId": instance.nf_instance_id,
            "nfType": instance.nf_type,
            "scope": scope,
            "targetNfType": target_type,
        }
        data = {**data, **additionnal_data}
        
        status, token = NFInstance.request_cn("NRF", data, "POST", "/oauth2/token", display=display)
        if 200 <= status < 300  and token : 
            return token["access_token"]

    def get_nf_info(instance: NFInstance, token:str, target_nf_type=None, additionnal_data={}, display=True) -> dict | None:
        """
        Performs NF (Network Function) discovery by querying the NRF for NF instance information.

        Args:
            instance (NFInstance): The NF instance making the request.
            token: Authorization token for the request.
            target_nf_type (optional): The type of NF to discover.
            additionnal_data (dict, optional): Additional data to include in the request.
            display (bool, optional): Whether to display request details.
        """
        uri = "/nnrf-disc/v1/nf-instances"
        data = {
            "requester-nf-type" : instance.nf_type,
            "target-nf-type" : target_nf_type
        }
        data = {**data, **additionnal_data}
        status, response = NFInstance.request_cn("NRF", data, "GET", uri, token=token, display=display)
        if 200 <= status < 300  : 
            return response
        else :
            return None
    
    # UDM REQUESTS 
    
    def get_am_data(supi, token, mcc, mnc, display=True):
        uri  = f"/nudm-sdm/v2/{supi}/am-data"
        data = {"plmn-id": json.dumps({"mcc": mcc, "mnc": mnc})}
        return NFInstance.request_cn("UDM", data, "GET", uri, token=token, display=display)

    def get_dnn(supi, token, mcc, mnc, display=True):
        uri  = f"/nudm-sdm/v2/{supi}/smf-select-data"
        data = {"plmn-id": json.dumps({"mcc": mcc, "mnc": mnc})}
        return NFInstance.request_cn("UDM", data, "GET", uri, token=token, display=display)

    def get_sm_data(supi, token, mcc, mnc, sst, sd, display=True):
        uri  = f"/nudm-sdm/v2/{supi}/sm-data"
        data = {
            "dnn": "internet",
            "plmn-id": json.dumps({"mcc": mcc, "mnc": mnc}),
            "single-nssai": json.dumps({"sst": sst, "sd": sd})
        }
        return NFInstance.request_cn("UDM", data, "GET", uri, token=token, display=display)