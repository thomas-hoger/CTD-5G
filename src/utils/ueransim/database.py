import httpx
import json

from src.utils.common import ip_list

WEBUI_PREFIX = f"http://{ip_list["WEBUI"]}:5000"

def _webui_token() -> str | None:
    """
    Authenticate with the web UI and retrieve an access token.
    Returns:
        str | None: The access token if authentication is successful, otherwise None.
    """
    
    login_data = {"username" : "admin", "password" : "free5gc"}
    login_url  = WEBUI_PREFIX + "/api/login"

    with httpx.Client(http1=True, verify=False) as client:
        response = client.request("POST", login_url, json=login_data, headers={})
        
    if 200 <= response.status_code <= 300 :
        return response.json()["access_token"]

def _add_subscriber(imsi:str, token:str) -> bool:
    """
    Adds a subscriber to the database using the provided IMSI and authentication token.
    Args:
        imsi (str): The IMSI (International Mobile Subscriber Identity) of the subscriber.
        token (str): Authentication token for the API request.
    Returns:
        bool: True if the subscriber was added successfully (HTTP 2xx or 3xx), False otherwise.
    """
    
    with open("./src/utils/ueransim/add_subscriber.json", "r", encoding="utf-8") as f:
        data = json.load(f)
        
    data["ueId"] = imsi
    url = WEBUI_PREFIX + "/api/subscriber/" + data["ueId"] + "/" + data["plmnID"]

    headers = {"Token" : token}

    with httpx.Client(http1=True, verify=False) as client:
        response = client.request("POST", url, json=data, headers=headers)
        
    return 200 <= response.status_code <= 300 
    
def add_multiple_subscribers(quantity:int, first_id:int=1) -> bool:
    """
    Adds multiple subscribers to the database, starting from a given ID.
    Args:
        quantity (int): Number of subscribers to add.
        first_id (int, optional): Starting ID for subscriber IMSIs. Defaults to 1.
    Returns:
        bool: True if all subscribers were added successfully and token was obtained, False otherwise.
    """
    
    results:list[bool] = []
    token = _webui_token()
    if token : 
        
        for i in range(quantity):
            imsi   = "imsi-20893" + '{:010d}'.format(first_id + i)
            result = _add_subscriber(imsi,token)
            results.append(result)
            
    return token is not None and all(results)