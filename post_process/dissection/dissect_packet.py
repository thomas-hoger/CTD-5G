import re

import pandas as pd
import pyshark
import tqdm
from pyshark.packet.packet import Packet

from .http2_parser import dissect_http2


def normalize_imsi(d: dict) -> dict:
    """
    Normalizes IMSI or SUCI values in a dictionary by extracting and unifying the IMSI representation.
    Modifies the input dictionary in place, replacing matching values with the unified IMSI string.
    """
    new_d = d.copy()
    for key, value in d.items():
        if value and isinstance(value, str):
            matched = re.search(r'suci-\d+-\d+-\d+-\d+-\d+-\d+-\d+', value)
            if not matched:
                matched = re.search(r'imsi-\d{15}', value)

            if matched:
                parts = matched.group().split("-")
                id_type = parts.pop(0)

                if id_type == "suci":
                    supi_type = int(parts[0])
                    if supi_type == 0:   # IMSI
                        unified_imsi = parts[1] + parts[2] + parts[6]
                    else:  # Network Access Identifier (NAI)
                        unified_imsi = ""
                else:
                    unified_imsi = parts[0]

                new_d[key] = value.replace(matched.group(),id_type)
                new_d["imsi"] = unified_imsi

    return new_d

def flatten_dict(d, parent_key='', sep='.') -> dict:
    """
    Recursively flattens a nested dictionary or list into a single-level dictionary with compound keys.

    Args:
        d (dict or list): The dictionary or list to flatten.
        parent_key (str, optional): The base key string for recursion. Defaults to ''.
        sep (str, optional): Separator between key levels. Defaults to '.'.

    Returns:
        dict: A flattened dictionary with compound keys representing the original nested structure.
    """
    flat = {}
    if isinstance(d, dict):
        for k, v in d.items():
            full_key = f"{parent_key}{sep}{k}" if parent_key else k
            flat.update(flatten_dict(v, full_key, sep=sep))
    elif isinstance(d, list):
        for idx, item in enumerate(d):
            full_key = f"{parent_key}[{idx}]"
            flat.update(flatten_dict(item, full_key, sep=sep))
    else:
        flat[parent_key] = d
    return flat

def dissect_packet(packet: Packet) -> dict:

    # Check for the IP layer
    if not hasattr(packet, 'ip'):
        return []

    # Information common to all packets
    packet_informations = {
        "common": {    # Fields that will be present in the graph
            "ip_src": str(packet.ip.src),
            "ip_dst": str(packet.ip.dst),
            "ts": float(packet.sniff_timestamp)
        },
        "protocols" : {}
    }

    # HTTP2 packets
    if 'HTTP2' in packet:
        dissected_pkt = dissect_http2(packet)
        for layer in dissected_pkt:
            if layer:

                new_layer = layer.copy()
                new_layer = flatten_dict(new_layer)
                new_layer = normalize_imsi(new_layer)

                if "http2" not in packet_informations["protocols"]:
                    packet_informations["protocols"]["http2"] = []

                packet_informations["protocols"]["http2"].append(new_layer)

    second_ip_layer_present = False
    for layer in packet.layers:
        for protocol in ["gtp", "ngap", "nas-5gs", "pfcp"]:
            if layer.layer_name == protocol:

                if protocol not in packet_informations["protocols"]:
                    packet_informations["protocols"][protocol] = []

                features = {key.replace(f"{protocol}.",""):value for key,value in layer._all_fields.items() if key and value}
                packet_informations["protocols"][protocol].append(features)

                if layer.layer_name == "gtp":
                    second_ip_layer_present = True

        if layer.layer_name == "ip" and second_ip_layer_present:
            packet_informations["protocols"]["ip"] = [{
                "ip_src" : layer.src,
                "ip_dst" : layer.dst
            }]

    return packet_informations

def dissect_packets(packets:pyshark.FileCapture, label_dataframe:pd.DataFrame) -> list[dict]:

    result = []
    for i, pkt in enumerate(tqdm.tqdm(packets, desc="Dissecting packets", unit="pkt", total=800000)):

        dissected_pkt   = dissect_packet(pkt)
        pkt_label_entry = label_dataframe.loc[i]

        # we don't keep the packet without protocols
        if dissected_pkt and len(dissected_pkt["protocols"])>0:
            dissected_pkt["common"]["is_attack"] = str(pkt_label_entry["is_attack"])
            dissected_pkt["common"]["type"] = pkt_label_entry["type"]
            result.append(dissected_pkt)

    return result
