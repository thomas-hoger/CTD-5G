import uuid
import base64
import datetime
import random
import os 
import yaml
import re

GNB_CONFIG_PATH = "config/gnbcfg.yaml"
UE_CONFIG_PATH = "config/uecfg.yaml"
MAX_TEMPORARY_NF = 10

ue_list = []  # Global list to store UserEquipment instances

# Get the IP list of the CN components
with open("./src/utils/addresses.yaml", "r", encoding="utf-8") as file:
    ip_list:dict = yaml.safe_load(file)
    
dn_domains = [
    "google.com",
    "github.com",
    "facebook.com",
    "twitter.com",
    "youtube.com",
    "wikipedia.org",
    "reddit.com",
    "stackoverflow.com",
    "bing.com",
    "yahoo.com",
    "amazon.com",
    "linkedin.com",
    "instagram.com",
    "pinterest.com",
]

# ------- Docker 

def docker_exec(container:str, command:str, read=True) -> str:
    "Executes a command in a Docker container and returns the output."
    # print(command)
    execution = os.popen(f"sudo docker exec {container} {command}")
    if read : # read can be blocking in certain cases
        return execution.read()

def ueransim_exec(command:str, read=True) -> str:
    "Executes a command in the UERANSIM container."
    return docker_exec("ueransim", command, read=read)

# ------- Variables Generation

def get_docker_iface_from_ip(docker_name:str,ipv4:str) -> str | None:
    pattern = re.compile(
        r"^\d+: (\S+):.*?\n(?:    .*\n)*?\s+inet " + re.escape(ipv4),
        re.MULTILINE
    )

    ip_a  = docker_exec(docker_name, "ip a")
    match = pattern.search(ip_a)
    if match : 
        return match.group(1)
  
def get_my_ip_from_prefix(prefix: str = "10.100.200") -> str | None:
    ip_output = os.popen("ip a").read()
    pattern = re.compile(rf"inet ({prefix}.\d+)")
    match = pattern.search(ip_output)
    if match:
        return match.group(1)
    return None

def generate_variables(ptype:str):
    """
    Generate a variable of a specified type with random or default values.
    Args:
        ptype (str): The type of variable to generate. Supported types include:
            - "uuid": A random UUID string.
            - "binary": A base64-encoded binary string or None.
            - "bytes": A base64-encoded byte string.
            - "string": A random string of length 10.
            - "date": The current date in ISO 8601 format.
            - "date-time": The current datetime in ISO 8601 format.
            - "float": A random positive float.
            - "double": A random positive double.
            - "integer": A random positive int32.
            - "int32": A random positive int32.
            - "int64": A random positive int64.
            - "boolean": A random boolean value.
            - "array": An array of 1 to 10 random integers.
    Returns:
        Union[str, int, float, bool, list, None]: The generated variable of the specified type.
        If the specified type is not supported, returns a string in the format "<ptype>".
    """

    values = {
        "uuid": str(uuid.uuid4()),  # UUID format
        "binary": base64.b64encode(bytes(random.getrandbits(8) for _ in range(10))).decode("utf-8") if random.choice([True, False]) else None,  # Binary string or None
        "bytes": base64.b64encode(bytes(random.getrandbits(8) for _ in range(10))).decode("utf-8"),  # Byte string
        "string": ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=10)),  # Random string of length 10
        "date": datetime.date.today().isoformat(),  # Current date in ISO 8601 format
        "date-time": datetime.datetime.now().isoformat(),  # Current datetime in ISO 8601 format
        "float": random.uniform(0, 1e6),  # Random positive float
        "double": random.uniform(0, 1e12),  # Random positive double (in Python, float is double precision)
        "integer": random.randint(0, 2**31 - 1),  # Random positive int32
        "int32": random.randint(0, 2**31 - 1),  # Random positive int32
        "int64": random.randint(0, 2**63 - 1),  # Random positive int64
        "boolean" : random.choice([True,False]),
        "array": [random.randint(0, 100) for _ in range(random.randint(1, 10))],  # Tableau de 1 à 10 entiers

    }
    if ptype in values : 
        return values[ptype]
    else : 
        return f"<{ptype}>"

