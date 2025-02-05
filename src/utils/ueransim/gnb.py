import re
import yaml

from src.utils.common import  ueransim_exec

class gNodeB:

    def get_registered_gnb() -> list[str]:
        "Returns a list of registered gNBs in the UERANSIM network."
        components = ueransim_exec("./nr-cli --dump")
        registered_gnb = re.findall(r"^UERANSIM-gnb-.*", components, re.MULTILINE)
        return registered_gnb

    def get_registered_ues_in_gnb(gnb:str) -> list[dict]:
        "Return a list of dictionaries containing ue-id, ran-ngap-id and amf-ngap-id for each UE connected to the specified gNB."
        ue_list = ueransim_exec(f"./nr-cli {gnb} -e 'ue-list'")
        return yaml.safe_load(ue_list) or []