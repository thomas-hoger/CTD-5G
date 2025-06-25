from src import *
from src.benign.procedures import random_benin
from src.utils.ueransim.ue import docker_exec
import os
import json
import threading
import sys
import time
import random
import subprocess


def docker_exec_live(container_name, command):
    full_cmd = ["sudo", "docker", "exec", container_name] + command.split()
    process = subprocess.Popen(
        full_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    try:
        for line in process.stdout:
            print(line, end="")
    except Exception as e:
        print(f"[ERROR] {e}")

    process.wait()


def export_active_ues(ue_list):
    path = "/dev/shm/ue_data"
    os.makedirs(path, exist_ok=True)
    file_path = os.path.join(path, "active_ues.json")
    with open(file_path, "w") as f:
        json.dump([ue.__dict__ for ue in ue_list], f, indent=2)


def start_benin(duration=10, sleep_range=(0.5, 0.5), random_seed=1):
    print("Starting Benin with time:", duration)
    end_time = time.time() + duration
    while time.time() < end_time:
        random_benin()
        time.sleep(random.uniform(*sleep_range))


def start_attack(duration=10, sleep_range=(0.5, 0.5), random_seed=1):
    print("Starting attack with time:", duration)

    docker_exec_live(
        "evil",
        "python -m src.attacks.start_attacks {} {} {} {}".format(
            duration, sleep_range[0], sleep_range[1], random_seed
        ),
    )
    # docker_exec(
    #     "evil",
    #     f"python start_attacks.py {duration} {sleep_range[0]} {sleep_range[1]} {random_seed}",
    # )


def main():
    input_duration = input("Enter simlation time in seconds (default 10): ")
    duration = int(input_duration) if input_duration else 10

    input_sleep_min = input("Enter minimum sleep time (default 0.5): ")
    input_sleep_max = input("Enter maximum sleep time (default 0.5): ")
    sleep_min = float(input_sleep_min) if input_sleep_min else 0.5
    sleep_max = float(input_sleep_max) if input_sleep_max else 0.5

    os.system("sudo echo OK!")

    print("#### CONFIG ####")
    print(f"Duration:    {duration} sec")

    print(f"Sleep range: {sleep_min} - {sleep_max} sec")
    print("#" * 16)
    thread_benin = threading.Thread(
        target=start_benin, args=(duration, (sleep_min, sleep_max))
    )
    thread_attack = threading.Thread(
        target=start_attack, args=(duration, (sleep_min, sleep_max))
    )

    thread_benin.start()
    thread_attack.start()
    thread_benin.join()
    thread_attack.join()


main()


# pour start les attack on fait 
from run_evil import available_attacks

def random_attack():
    attack_name = random.choice(available_attacks)
    docker_exec("evil", f"python run_host.py {attack_name}")