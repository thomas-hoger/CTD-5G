from src.utils.ueransim.ue import UserEquipment
from src.utils.ueransim.session import PDUSession
from src.utils.protocols.api_cn.instance import NFInstance
from src.utils.common import dn_domains, MAX_TEMPORARY_NF, ue_list
import time
import random

class Benigns:
    
    # UE REGISTRATION AND DEREGISTRATION
    
    def register_random_ue() -> bool:
        imsi = UserEquipment.get_available_imsi()
        print(f"Registering {imsi}")
        return UserEquipment.register_new(imsi) is not None

    def deregister_random_ue() -> bool:
        ue: UserEquipment = random.choice(ue_list)
        print(f"Deregistering {ue.imsi}")
        return ue.deregister()

    # UE STATE MANAGEMENT

    def set_random_ue_idle() -> bool:
        active_ues = UserEquipment.get_connected_ues()
        ue: UserEquipment = random.choice(active_ues)
        print(f"Setting UE {ue.imsi} to idle")
        return ue.context_release()

    def uplink_wake_random_ue() -> bool:
        idle_ues = UserEquipment.get_idle_ues()
        ue: UserEquipment = random.choice(idle_ues)
        print(f"Waking UE {ue.imsi} with uplink")
        return ue.uplink_wake()

    def downlink_wake_random_ue() -> bool:
        idle_ues = UserEquipment.get_idle_ues()
        ue: UserEquipment = random.choice(idle_ues)
        print(f"Waking UE {ue.imsi} with downlink")
        return ue.downlink_wake()

    # PDU SESSION MANAGEMENT

    def restart() -> bool:
        sessions = PDUSession.get_sessions()
        session: PDUSession = random.choice(sessions)
        print(f"Restarting PDU session of UE {session.address}")
        return session.restart()

    # USER TRAFFIC 

    def user_traffic() -> bool:
        active_ues = UserEquipment.get_connected_ues()
        ue: UserEquipment = random.choice(active_ues)
        dn_domain = random.choice(dn_domains)
        pkts_nbr = random.randint(10, 20)
        session = random.choice(ue.sessions)
        print(f"Sending {pkts_nbr} uplink packets from UE {ue.imsi} to {dn_domain} via session {session.address}")
        return session.uplink_traffic(pkts_nbr, dn_domain) 

    # NF MANAGEMENT

    def add_random_nf() -> bool:
        instance:NFInstance = NFInstance.add_random_nf(display=False)
        print("Adding random NF")
        
        if instance:
            print(f"{instance.nf_type} {instance.nf_instance_id} added")
            NFInstance.nf_list.append(instance)
            time.sleep(1) # Wait for the NF to be added
            return True
        
        return False

    def remove_random_nf() -> bool:
        instance: NFInstance = random.choice(NFInstance.nf_list)
        print(f"Removing {instance.nf_type} instance {instance.nf_instance_id}")

        # Get a token for this NF
        scope = "nnrf-nfm"
        target_type = "NRF"
        token = instance.get_token(scope, target_type)
        
        if token :
            success = instance.remove_nf(token)
            
            if success:
                NFInstance.nf_list.remove(instance)
                time.sleep(1)  # Wait for the NF to be removed
                return True
            
        return False
        
# PICK RANDOM PROCEDURE

def random_benign() -> str:
    
    possible_procedures = []
    
    # Force the first function to be the registration of an UE
    # Because its mandatory to use some attacks
    if len(ue_list) < 1:
        return Benigns.register_random_ue
    
    if len(UserEquipment.get_available_imsi()) > 0:
        possible_procedures.append(Benigns.register_random_ue)
        
    if len(ue_list) > 1: # leave at least 1 up
        possible_procedures.append(Benigns.deregister_random_ue)
        
    if len(UserEquipment.get_connected_ues()) > 1: # leave at least 1 connected
        possible_procedures.append(Benigns.set_random_ue_idle)
    
    if len(UserEquipment.get_connected_ues()) > 0: 
        possible_procedures.append(Benigns.user_traffic)
        
    if len(UserEquipment.get_idle_ues()) > 0:
        possible_procedures.append(Benigns.uplink_wake_random_ue)
        possible_procedures.append(Benigns.downlink_wake_random_ue)
        
    if len(PDUSession.get_sessions()) > 0:
        possible_procedures.append(Benigns.restart)
        
    if len(NFInstance.nf_list) < MAX_TEMPORARY_NF:  # Limit the number of NFs to 5
        possible_procedures.append(Benigns.add_random_nf)
        
    if len(NFInstance.nf_list) > 1: # leave at least 1 up
        possible_procedures.append(Benigns.remove_random_nf)
        
    procedure = random.choice(possible_procedures)
    return procedure

