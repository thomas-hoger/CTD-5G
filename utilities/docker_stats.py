import docker
import csv
import time
from datetime import datetime


def calculate_cpu_percent(stats):
    cpu_delta = (
        stats["cpu_stats"]["cpu_usage"]["total_usage"]
        - stats["precpu_stats"]["cpu_usage"]["total_usage"]
    )
    system_delta = (
        stats["cpu_stats"]["system_cpu_usage"]
        - stats["precpu_stats"]["system_cpu_usage"]
    )
    cpu_count = len(stats["cpu_stats"]["cpu_usage"].get("percpu_usage", []))
    if system_delta > 0.0 and cpu_delta > 0.0:
        cpu_percent = (cpu_delta / system_delta) * cpu_count * 100.0
    else:
        cpu_percent = 0.0
    return cpu_percent


def get_stats(container):
    stats = container.stats(stream=False)
    mem_usage = stats["memory_stats"]["usage"]
    mem_limit = stats["memory_stats"].get("limit", 1)
    mem_percent = (mem_usage / mem_limit) * 100.0
    cpu_percent = calculate_cpu_percent(stats)
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "cpu_percent": round(cpu_percent, 2),
        "mem_usage_MB": round(mem_usage / (1024**2), 2),
        "mem_limit_MB": round(mem_limit / (1024**2), 2),
        "mem_percent": round(mem_percent, 2),
    }


def monitor_container(container_name, csv_filename="docker_stats.csv", interval=60):
    client = docker.from_env()
    # client = docker.DockerClient(base_url="unix:///var/run/docker.sock")
    container = client.containers.get(container_name)

    with open(csv_filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "timestamp",
                "cpu_percent",
                "mem_usage_MB",
                "mem_limit_MB",
                "mem_percent",
            ],
            delimiter=";",
        )
        writer.writeheader()

    while True:
        stats = get_stats(container)
        with open(csv_filename, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=stats.keys(), delimiter=";")

            writer.writerow(stats)
        print(
            f"[{stats['timestamp']}] CPU: {stats['cpu_percent']}%, RAM: {stats['mem_usage_MB']}MB ({stats['mem_percent']}%)"
        )
        time.sleep(interval)


if __name__ == "__main__":
    monitor_container("upf", "stats.csv", interval=60)
