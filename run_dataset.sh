#!/bin/bash

# Kill the previous tcpdump and python processes if they are running
echo "[+] Killing previous tcpdump and python processes..."
sudo pkill -f "tcpdump"
sudo pkill -f "python -u"

# Start tcpdump in the background
echo "[+] Starting tcpdump..."
sudo tcpdump -i br-free5gc -w "./output/5GCTD.pcap" -C 200 > /dev/null 2>&1 &

# Launch benign traffic scripts with nohup in the background
echo "[+] Launching benign traffic..."
sudo nohup python -u run.py -t benign -d 600 > ./output/benign.txt 2>&1 &

# Wait for 60 seconds to ensure benign traffic is captured
echo "[+] Waiting 60 seconds..."
sleep 60

# Launch attacks traffic scripts with nohup in the background
echo "[+] Launching attack traffic..."
sudo nohup python -u run.py -t attack -d 600 > ./output/attack.txt 2>&1 &
