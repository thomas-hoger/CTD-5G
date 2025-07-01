import sys

from src.attacks.procedures import Attacks

attack_id = int(sys.argv[1])
attack_name = sys.argv[2]

available_attacks = [name for name in dir(Attacks) if callable(getattr(Attacks, name)) and not name.startswith("_")]

if attack_id and attack_name and attack_name in available_attacks :
        
    # Run the attack
    attack = getattr(Attacks, attack_name)
    success = attack()
    print(success)