from src.benign.procedures import random_benign
from src.attacks.procedures import random_attack
from src.utils.common import docker_exec
from src.utils.ueransim.ue import ue_list, UEState
from src.utils.ueransim.session import PDUSession
from src.utils.protocols.api_cn.instance import NFInstance
from src.marker.generation import Marker, marker_base
from src.utils.ueransim.database import add_multiple_subscribers, known_imsis

from enum import Enum
from datetime import datetime, timedelta
import argparse

from scapy.all import send
import os

class TrafficType(Enum):
    BENIGN = "benign"
    ATTACK = "attack"
        
def parse_args():
    parser = argparse.ArgumentParser(description="Network simulation script")
    
    parser.add_argument(
        "-d", "--duration",
        type=int,
        default=1,
        help="Simulation time in minutes (default: 1)"
    )

    parser.add_argument(
        "-t", "--traffic-type",
        type=str,
        choices=[t_type.value for t_type in TrafficType],
        required=True,
        help="Traffic type: benign or attack"
    )

    return parser.parse_args()

args = parse_args()
duration = args.duration
traffic_type = TrafficType(args.traffic_type)
is_attack = int(traffic_type == TrafficType.ATTACK)

# If 1000 IMSI are not in the database we add them
NUMBER_OF_KNOWN_UE = 1000
if len(known_imsis) < NUMBER_OF_KNOWN_UE:
    print(f"Registering {NUMBER_OF_KNOWN_UE} imsi in the databse, it could take some time...")
    add_multiple_subscribers(quantity=NUMBER_OF_KNOWN_UE, first_id=1)
        
# Run attacks or benign
end_time = datetime.now() + timedelta(minutes=duration)
count = 1
while datetime.now() < end_time:
    
    # Benign
    if traffic_type == TrafficType.BENIGN:
        procedure = random_benign()
        procedure_name = procedure.__name__
        
    # Attacks
    else : 
        procedure_name = random_attack()
        
    # ---- Send the first marker
    marker_start = Marker(
        id = count,
        start = 1,
        type = procedure_name,
        attack = is_attack
    )
    send(marker_base / marker_start, verbose=False)
    
    # Print the procedure
    prefix = "[Attack Traffic]" if traffic_type == TrafficType.ATTACK else "[Benign Traffic]"
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"{'='*30}\n{prefix} [{timestamp}] Running procedure {count}: {procedure_name}")
      
    # Benign
    if traffic_type == TrafficType.BENIGN:
        result = procedure()
        
    # Attacks
    else : 
        args = ""
        if procedure_name in ["uplink_spoofing", "pfcp_in_gtp"]:
            ue_addr = PDUSession.get_random_ip()
            teid    = PDUSession.get_teid_by_ip(ue_addr)
            args    = f"{ue_addr} {teid}"
            
        execution = docker_exec("evil", f"python evil.py {count} {procedure_name} {args}")
        result = True if "True" in execution else False
        print(execution)
        
    # ---- Send the second marker
    marker_stop = Marker(
        id = count,
        start = 0,
        type = procedure_name,
        attack = is_attack
    )
    send(marker_base / marker_stop, verbose=False)
        
    # Print the result
    result = "✅" if result else "❌"
    print(f"Procedure finished with result: {result}")
    
    # For benign print additionnal info
    if traffic_type == TrafficType.BENIGN:
    
        # Print state of the ues
        formated_ue_list = [f"UE-{ue.imsi[-4:]} {"😴" if ue.state == UEState.IDLE else "😀"}" for ue in ue_list]
        print("Current UE states :", ", ".join(formated_ue_list))
        
        # Print state of the ues
        print("Current NFs :", ", ".join([nf.nf_instance_id.split("-")[0] for nf in NFInstance.nf_list]))
        
    # sleep 2 (+/- 1) seconds between each iteration
    count += 1
    
os.popen("pkill -f tcpdump")