import random

import pandas as pd
import tqdm
from scapy.all import Packet, bind_layers
from scapy.fields import BitField, IntField, StrFixedLenField
from scapy.layers.inet import IP, UDP
from scapy.plist import PacketList


class Marker(Packet):
    name = "Marker"
    fields_desc = [
        IntField("id", 0),
        BitField("start", 0, 1),  # flag 1 bit
        BitField("attack", 0, 1),  # flag 1 bit
        BitField("padding", 0, 6), # to align on 1 byte
        StrFixedLenField("type", b"", length=20)
    ]

bind_layers(UDP, Marker, dport=9999)
bind_layers(UDP, Marker, sport=9999)

def _get_random_ip(ip_to_avoid:str):

    suffix_to_avoid = int(ip_to_avoid.split(".")[-1])
    suffix_pool = list(range(2,17))
    if suffix_to_avoid in suffix_pool:
        suffix_pool.remove(suffix_to_avoid)

    return f"10.100.200.{random.choice(suffix_pool)}" # random nf from the CN

def _replace_address(pkt: PacketList, ip_to_replace:str, new_ip:str) -> PacketList:
    """
    Replaces the source and destination IP and MAC addresses in packets matching a given IP.
    Args:
        packet (Packet): Packet to process.
        ip_to_replace (str): IP address to be replaced.
    Returns:
        PacketList: New PacketList with updated addresses.
    """
    
    if IP in pkt :

        if pkt[IP].src == ip_to_replace :
            pkt[IP].src = new_ip

        if pkt[IP].dst == ip_to_replace :
            pkt[IP].dst = new_ip

    return pkt

def process(packets: PacketList, evil_ip: str) -> tuple[PacketList, pd.DataFrame]:

    processed_packets = []
    df_rows           = []

    attack_marker_start = None
    benign_marker_start = None
    attack_ip = ""
    benign_ip = ""

    for i, pkt in enumerate(tqdm.tqdm(packets, desc="Clean and label packets", unit="pkt", total=len(packets))):

        # Find markers
        if pkt.haslayer(Marker):

            marker:Marker = pkt[Marker]
            is_attack = int(marker.attack)

            # If the marker is a start and the interval don't already existe we create it
            if marker.start == 1:

                if is_attack :
                    attack_marker_start = marker
                else :
                    benign_marker_start = marker

            # If the marker is a stop we modify its end index
            elif is_attack :
                attack_marker_start = None
                attack_ip = ""
            else :
                benign_marker_start = None
                benign_ip = ""


        # If its not a marker, we process the packet
        elif IP in pkt :

            is_attack = 0

            # 10.100.200.66 is always an attacker
            if pkt[IP].src == evil_ip or pkt[IP].dst == evil_ip:

                is_attack = 1
                if not attack_ip :
                    ip_to_avoid = pkt[IP].src if pkt[IP].src != evil_ip else pkt[IP].dst
                    attack_ip = _get_random_ip(ip_to_avoid)

                _replace_address(pkt, evil_ip, attack_ip)

            # 10.100.200.1 can be either an attacker or a benign
            if pkt[IP].src == "10.100.200.1" or pkt[IP].dst == "10.100.200.1":

                if not benign_ip :
                    ip_to_avoid = pkt[IP].src if pkt[IP].src != "10.100.200.1" else pkt[IP].dst
                    benign_ip = _get_random_ip(ip_to_avoid)

                _replace_address(pkt, "10.100.200.1", benign_ip)

            # Some packets
            if is_attack and attack_marker_start is not None :
                p_type = attack_marker_start.type.decode()
            elif benign_marker_start is not None:
                p_type = benign_marker_start.type.decode()
            else :
                p_type    = "unknown"
                is_attack = -1

            processed_packets.append(pkt)

            df_rows.append({
                "ts": pkt.time,
                "id": i,
                "is_attack": is_attack,
                "type": p_type
            })

            # if i > 15000:
            #     break

    df = pd.DataFrame(df_rows)
    return processed_packets, df


