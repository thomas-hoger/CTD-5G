#!/bin/bash

# Start tcpdump in the background
echo "[+] Starting tcpdump..."
sudo tcpdump -i br-free5gc -w "./output/5GCTD.pcap" -C 200 > /dev/null 2>&1 &

# Launch attack and benign traffic scripts with nohup in the background
echo "[+] Launching attack and benign traffic..."
sudo nohup python -u run.py -t attack -d 600 > ./output/attack.txt 2>&1 &
sudo nohup python -u run.py -t benign -d 600 > ./output/benign.txt 2>&1 &
