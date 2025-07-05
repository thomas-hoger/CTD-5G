#!/bin/bash

# Démarrer tcpdump en arrière-plan
echo "[+] Démarrage de tcpdump..."
sudo tcpdump -i br-free5gc -w "./output/5GCTD.pcap" > /dev/null 2>&1 &

# Lancer les scripts attack et benign avec nohup en arrière-plan
echo "[+] Lancement du trafic attack et benign..."
sudo nohup python -u run.py -t attack -d 600 > ./output/attack.txt 2>&1 &
sudo nohup python -u run.py -t benign -d 600 > ./output/benign.txt 2>&1 &
