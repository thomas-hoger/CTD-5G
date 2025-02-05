from scapy.all import rdpcap, wrpcap, IP, Raw, Ether
from ipaddress import ip_address
import random, csv
from scapy.all import IP, UDP, Raw, send
import sys


def create_marker_packet(src_ip, dst_ip, marker_str, sport=5555, dport=9999):
    payload = Raw(load=marker_str.encode())
    pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / payload
    return pkt


def send_marker_packet(marker_name, src_ip="111.111.111.111", dst_ip="222.222.222.222"):
    marker = create_marker_packet(src_ip, dst_ip, marker_name)
    send(marker)


def handle_markers(marker_name, func):
    send_marker_packet(marker_name=f"{marker_name}_START")
    print(
        f"---------------------- Marker {marker_name}_START Sent ---------------------"
    )
    print(f"###   Attack {marker_name} Status: STARTED")
    res = func()
    print(f"###   Attack {marker_name} Status: FINISHED")

    send_marker_packet(marker_name=f"{marker_name}_END")
    print(f"---------------------- Marker {marker_name}_END Sent ---------------------")
    return res


def replace_ip_and_mac_between_markers(
    input_pcap,
    output_pcap,
    output_csv,
    start_marker,  # marqueur de debut
    end_marker,  # marqueur de fin
    src_ip_to_replace,  # (evil)
    new_ip,  # ca sera une ip random dans le couple de 3 ips
    new_mac_src=None,  # mac correspondante (ip => mac fonctionne en couples)
):
    packets = rdpcap(input_pcap)
    start_idx = end_idx = None

    indices_to_remove = set()

    labeled_timestamps = list()

    # calcule index balises
    for i, pkt in enumerate(packets):
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            if start_marker.encode() in payload and start_idx is None:
                start_idx = i
                indices_to_remove.add(i)
            elif end_marker.encode() in payload and start_idx is not None:
                end_idx = i
                indices_to_remove.add(i)
                break

    if start_idx is None or end_idx is None:
        print("[-] Balises non trouvées")
        return

    print(f"[i] Modifications entre paquets {start_idx} et {end_idx}")

    # replace mac/ip src
    for pkt in packets[start_idx : end_idx + 1]:
        modified = False
        # IP source
        if IP in pkt:
            if pkt[IP].src == src_ip_to_replace:
                pkt[IP].src = new_ip
                del pkt[IP].chksum
                if new_mac_src and pkt.haslayer(Ether):
                    pkt[Ether].src = new_mac_src
                    modified = True

            if pkt[IP].dst == src_ip_to_replace:
                pkt[IP].dst = new_ip
                del pkt[IP].chksum
                if new_mac_src and pkt.haslayer(Ether):
                    pkt[Ether].dst = new_mac_src
                    modified = True

        # modifie le payload raw pour modifier toutes les occurences
        if pkt.haslayer(Raw):
            raw = pkt[Raw].load
            pkt[Raw].load = raw.replace(
                ip_address(src_ip_to_replace).packed, ip_address(new_ip).packed
            )

        if modified and hasattr(pkt, "time"):
            labeled_timestamps.append(pkt.time)

    filtered_packets = [
        pkt for i, pkt in enumerate(packets) if i not in indices_to_remove
    ]
    wrpcap(output_pcap, filtered_packets)

    print(f"[+] Nouveau PCAP sauvegardé : {output_pcap}")

    print(f"[i] Exportation des labels... ")
    with open(output_csv, "a", newline="") as f:
        wr = csv.writer(f)
        for ts in labeled_timestamps:
            wr.writerow([ts])

    print(f"[+] Timestamps enregistrés dans : {output_csv}")


def apply_ip_mac_replacement_for_markers(
    input_pcap,
    output_pcap,
    output_csv,
    markers,  # liste marqueurs
    src_ip_to_replace,  # evil
    ip_list,  # liste des 3 ips
    mac_list,  # liste des 3 macs
):
    if len(ip_list) != len(mac_list):
        raise ValueError("ip_list et mac_list doivent être de même longueur")

    packets = rdpcap(input_pcap)
    wrpcap(output_pcap, packets)  # on écrit une copie initiale

    for marker in markers:
        idx = random.randint(0, len(ip_list) - 1)
        ip = ip_list[idx]
        mac = mac_list[idx]  # c'est ici qu'on voit qu'ils fonctionnent en couple

        print(f"[i] {marker}: remplacement IP -> {ip}, MAC -> {mac}")

        replace_ip_and_mac_between_markers(
            input_pcap=output_pcap,
            output_pcap=output_pcap,
            output_csv=output_csv,
            start_marker=f"{marker}_START",  # marqueur de debut
            end_marker=f"{marker}_END",  # marqueur de fin
            src_ip_to_replace=src_ip_to_replace,  # evil
            new_ip=ip,  # iplist[idx]
            new_mac_src=mac,  # maclist[idx] couple n°idx
        )

    print(f"[+] Modifications terminées dans : {output_pcap}")


if __name__ == "__main__":
    # Utilisation
    apply_ip_mac_replacement_for_markers(
        input_pcap="input/exemple_multiple_marker.pcap",
        output_pcap="output/exemple_multiple_marker_processed.pcap",
        output_csv="output/multiple_labeled_timestamps.csv",
        markers=[
            "balise1",
            "balise2",
            "balise3",
            "balise4",
        ],
        src_ip_to_replace="140.93.90.69",
        ip_list=[
            "1.1.1.1",
            "2.2.2.2",
            "3.3.3.3",
        ],
        mac_list=[
            "aa:bb:cc:00:00:01",
            "aa:bb:cc:00:00:02",
            "aa:bb:cc:00:00:03",
        ],
    )
