import sys
import time 
import random

from src.attacks.api_cn.cn_mitm import CNMitm
from src.utils.protocols.api_cn.instance import NFInstance


def main():

    available_attacks = [
        "cn_mitm"
    ]
    
    attack_name = sys.argv[1]
    match attack_name:
        
        case "cn_mitm":
            nf_type = NFInstance.get_random_nf_type()
            CNMitm.start(nf_type)
            time_to_sleep = random.randint(50, 70)
            time.sleep(time_to_sleep)
            CNMitm.start(nf_type)

        case _:
            print(f"Unknown attack: {attack_name}, available attacks : {", ".join(available_attacks)}")
            return

if __name__ == "__main__":
    main()