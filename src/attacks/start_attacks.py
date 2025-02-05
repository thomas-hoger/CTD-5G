import time, random, sys, os
from src.attacks.attacks_labelized import *
from src import ip_list
import json


def read_active_ues():
    path = "/dev/shm/ue_data"
    file_path = os.path.join(path, "active_ues.json")
    if not os.path.exists(file_path):
        return []
    with open(file_path, "r") as f:
        return json.load(f)


def random_attack():
    attack_functions = [
        pfcp_session_establishment_flood_labelized,
        pfcp_session_deletion_flood_labelized,
        pfcp_session_modification_far_drop_bruteforce_labelized,
        pfcp_session_modification_far_dupl_bruteforce_labelized,
        pfcp_seid_fuzzing_labelized,
        pfcp_far_fuzzing_labelized,
        pfcp_hijack_far_manipulation_labelized,
        cn_mitm_labelized,
        free5gcCNFuzzing_labelized,
    ]
    random.choice(attack_functions)(
        ip_list["EVIL"],
    )


def main():
    duration = int(sys.argv[1])
    sleep_range = (float(sys.argv[2]), float(sys.argv[3]))
    random_seed = int(sys.argv[4])
    random.seed(random_seed)

    print(f"---------- STARTING ATTACKS ----------")
    print(f"Duration:    {duration} sec")
    print(f"Sleep range: {sleep_range[0]} - {sleep_range[1]} sec")
    print(f"Random seed: {random_seed}")
    print(f"--------------------------------------")

    dict_ues = read_active_ues()
    print(f"Active UEs: {dict_ues}")
    end_time = time.time() + duration
    while time.time() < end_time:
        random_attack()
        time.sleep(random.uniform(*sleep_range))


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print(
            "Usage: python start_attacks.py <duration> <sleep_min> <sleep_max> <random_seed>"
        )
        sys.exit(1)
    main()
