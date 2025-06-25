import sys
import time 
import random

from src.attacks.api_cn.cn_mitm import CNMitm
from src.attacks.api_cn.cn_fuzzing import CNFuzzing
from src.utils.protocols.api_cn.instance import NFInstance

available_attacks = [
    "cn_mitm",
    "fuzz"
]

def main():

    attack_name = sys.argv[1]
    match attack_name:
        
        # Run MITM for ~60 seconds
        case "cn_mitm":
            nf_type = NFInstance.get_random_nf_type()
            CNMitm.start(nf_type)
            time_to_sleep = int(random.normalvariate(120, 10))
            time.sleep(time_to_sleep)
            CNMitm.start(nf_type)
            
        # Fuzz a random NF for 100 packet (10 iterations of 10 different urls)
        case "fuzz":
            nf_list = ["NRF", "UDM", "AMF"]
            nf = random.choice(nf_list)
            CNFuzzing().fuzz(nf, nb_file=1, nb_url=10, nb_ite=10, nb_method=1)

        case _:
            print(f"Unknown attack: {attack_name}, available attacks : {", ".join(available_attacks)}")
            return

if __name__ == "__main__":
    main()