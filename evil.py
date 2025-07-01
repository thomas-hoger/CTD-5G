import sys

from src.attacks.procedures import Attacks
from src.utils.ueransim.session import PDUSession

attack_id = int(sys.argv[1])
attack_name = sys.argv[2]

available_attacks = [name for name in dir(Attacks) if callable(getattr(Attacks, name)) and not name.startswith("_")]

if attack_id and attack_name and attack_name in available_attacks :
        
    # Run the attack
    attack = getattr(Attacks, attack_name)
    
    if attack_name in ["uplink_spoofing", "pfcp_in_gtp"]:
        ue_addr = PDUSession.get_random_ip()
        teid = PDUSession.get_teid_by_ip(ue_addr)
        success = attack(ue_addr, teid)
    else :
        success = attack()
        
    print(success)