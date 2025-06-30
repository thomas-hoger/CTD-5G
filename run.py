from src.benign.procedures import random_benign
from src.attacks.procedures import random_attack
from src.utils.ueransim.ue import docker_exec

import random
from enum import Enum
from datetime import datetime, timedelta
import time
import argparse


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
        
# Run attacks or benign
end_time = datetime.now() + timedelta(minutes=duration)
while datetime.now() < end_time:
    
    # Benign
    if traffic_type == TrafficType.BENIGN:
        procedure = random_benign()
        procedure_name = procedure.__name__
        print(f"{'='*30}\n[Benign Traffic] Running procedure: {procedure_name}")
        result = procedure()
        
    # Attacks
    else : 
        procedure_name = random_attack()
        print(f"{'='*30}\n[Attack Traffic] Running procedure: {procedure_name}")
        execution = docker_exec("evil", f"python evil.py {procedure_name}")
        print(execution)
        result = True if execution else False
        
    # Print the result
    result = "✅" if result else "❌"
    print(f"Procedure '{procedure_name}' finished with result: {result}")
        
    # sleep 2 (+/- 1) seconds between each iteration
    time_to_sleep = int(random.normalvariate(2, 1))