from src.utils.ueransim.ue import UserEquipment
from src.utils.ueransim.session import PDUSession
from src.utils.protocols.api_cn.instance import NFInstance
from src.utils.common import dn_domains, MAX_TEMPORARY_NF, ue_list
import time
import random

class BenignProcedure:
    
    # UE REGISTRATION AND DEREGISTRATION
    
    def register_random_ue() -> bool:
        imsi = UserEquipment.get_available_imsi()
        return UserEquipment.register_new(imsi) is not None

    def deregister_random_ue() -> bool:
        registered_ues = UserEquipment.get_registered()
        ue: UserEquipment = random.choice(registered_ues)
        return ue.deregister()

    # UE STATE MANAGEMENT

    def set_random_ue_idle() -> bool:
        active_ues = UserEquipment.get_connected_ues()
        ue: UserEquipment = random.choice(active_ues)
        return ue.context_release()

    def uplink_wake_random_ue() -> bool:
        idle_ues = UserEquipment.get_idle_ues()
        ue: UserEquipment = random.choice(idle_ues)
        return ue.uplink_wake()

    def downlink_wake_random_ue() -> bool:
        idle_ues = UserEquipment.get_idle_ues()
        ue: UserEquipment = random.choice(idle_ues)
        return ue.downlink_wake()

    # PDU SESSION MANAGEMENT

    def restart():
        sessions = PDUSession.get_sessions()
        session: PDUSession = random.choice(sessions)
        session.restart()

    # USER TRAFFIC 

    def user_traffic() -> bool:
        active_ues = UserEquipment.get_connected_ues()
        ue: UserEquipment = random.choice(active_ues)
        dn_domain = random.choice(dn_domains)
        pkts_nbr = random.randint(1, 10)
        session = random.choice(ue.sessions)
        return session.uplink_traffic(pkts_nbr, dn_domain) 

    # NF MANAGEMENT

    def add_random_nf() -> bool:
        instance = NFInstance.add_random_nf()
        
        if instance:
            NFInstance.nf_list.append(instance)
            time.sleep(1) # Wait for the NF to be added
            return True
        
        return False

    def remove_random_nf() -> bool:
        instance: NFInstance = random.choice(NFInstance.nf_list)

        # Get a token for this NF
        scope = "nnrf-nfm"
        target_type = "NRF"
        token = instance.get_token(scope, target_type, display=False)
        
        if token :
            status, _ = instance.remove_nf(token, display=False)
            
            if status == 200 or status == 204:
                NFInstance.nf_list.remove(instance)
                time.sleep(1)  # Wait for the NF to be removed
                return True
            
        return False
        
    # PICK RANDOM PROCEDURE

    def random_benign() -> bool:
       
        possible_procedures = []
        
        if len(UserEquipment.get_available_imsi()) > 0:
            possible_procedures.append(BenignProcedure.register_random_ue)
            
        if len(ue_list) > 0:
            possible_procedures.append(BenignProcedure.deregister_random_ue)
            
        if len(UserEquipment.get_connected_ues()) > 0:
            possible_procedures.append(BenignProcedure.set_random_ue_idle)
            possible_procedures.append(BenignProcedure.user_traffic)
            
        if len(UserEquipment.get_idle_ues()) > 0:
            possible_procedures.append(BenignProcedure.uplink_wake_random_ue)
            possible_procedures.append(BenignProcedure.downlink_wake_random_ue)
            
        if len(PDUSession.get_sessions()) > 0:
            possible_procedures.append(BenignProcedure.restart)
            
        if len(NFInstance.nf_list) < MAX_TEMPORARY_NF:  # Limit the number of NFs to 5
            possible_procedures.append(BenignProcedure.add_random_nf)
            
        if len(NFInstance.nf_list) > 0:
            possible_procedures.append(BenignProcedure.remove_random_nf)
            
        procedure = random.choice(possible_procedures)
        result: bool = procedure()
        
        if result :
            print(f"Successfully executed benign {procedure.__name__}")
        else:
            print(f"Failed to execute benign {procedure.__name__}")
            
        return result

