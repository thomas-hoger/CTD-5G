import sys

from src.attacks.procedures import Attacks
from src.marker.generation import AttackMarker, marker_base

from scapy.all import send
import datetime

attack_id = int(sys.argv[1])
attack_name = sys.argv[2]

available_attacks = [name for name in dir(Attacks) if callable(getattr(Attacks, name)) and not name.startswith("_")]

if attack_id and attack_name and attack_name in available_attacks :

    # Send the first marker
    marker_start = AttackMarker(
        id = attack_id,
        start = 1,
        attack_type = attack_name
    )
    send(marker_base / marker_start)
    
    # Run the attack
    attack = getattr(Attacks, attack_name)
    success = attack()

    # Send the second marker
    marker_start = AttackMarker(
        id = attack_id,
        start = 0,
        attack_type = attack_name
    )
    send(marker_base / marker_start)
    
    status    = "✅" if success else "❌"
    line      = f"[{datetime.now()}] Attack: {attack_name} {status}\n"

    file_path = "./output/attacks.log"
    with open(file_path, "a", encoding="utf-8") as f:
        f.write(line)
