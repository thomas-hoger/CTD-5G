import os
import json
import yaml
import pyshark

import pandas as pd
from tqdm import tqdm
from scapy.all import rdpcap, wrpcap

from post_process.trace_labelling import process
from post_process.dissection.dissect_packet import dissect_packets
from post_process.dissection_clean import dissection_clean


with open("./src/utils/addresses.yaml", "r", encoding="utf-8") as file:
    ip_list = yaml.safe_load(file)

folder = "./output"

# 1 - Process and label packets
for filename in tqdm(os.listdir(folder), desc="Labelling and processing", unit="file"):
    if filename.endswith(".pcap"):
        
        packets = rdpcap(os.path.join(folder, filename))
        packets_processed, df = process(packets, ip_list["EVIL"])
        
        # Export labels
        os.makedirs(os.path.join(folder, "labels"), exist_ok=True)
        df.to_csv(os.path.join(folder, "labels", filename.split(".")[0] + ".csv"), index=False)
        
        # Export processed pcap
        os.makedirs(os.path.join(folder, "processed"), exist_ok=True)
        wrpcap(os.path.join(folder, "processed", filename), packets_processed)

# 2 - Dissection
for filename in tqdm(os.listdir(folder), desc="Dissection", unit="file"):
    
    packets = pyshark.FileCapture(os.path.join(folder, "processed", filename))
    df = pd.read_csv(os.path.join(folder, "labels", filename.split(".")[0] + ".csv"))
    dissection_json = dissect_packets(packets, df)
    
    banned_features = [
        "versions",
        "scheme",
        "subscribedUeAmbr",
        "dnnInfos",
        "jwt.alg",
        "jwt.typ",
        "start_time",
        "end_time",
        "NAS_PDU",
    ]

    dissection_json_clean = dissection_clean(dissection_json, banned_features)
    
    os.makedirs(os.path.join(folder, "dissection"), exist_ok=True)
    with open(os.path.join(folder, "dissection", filename.split(".")[0] + ".json"), "w") as f:
        json.dump(dissection_json_clean, f)