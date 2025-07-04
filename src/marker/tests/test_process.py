from src.marker.post_process import _extract_intervals, _replace_addresses, process, get_packets_by_type
from src.marker.generation import Marker, marker_base
from src.utils.common import ip_list

from scapy.layers.inet import IP, UDP
from scapy.all import rdpcap, send, Raw

import subprocess
import time
import os
import signal
import pytest

CAPTURE_FILE = "./src/marker/tests/example.pcap"

@pytest.fixture(scope='module', autouse=True)
def capture():
    
    iface = "br-free5gc"

    # Start tcpdump
    tcpdump_proc = subprocess.Popen(
        ["tcpdump", "-i", iface, "-w", CAPTURE_FILE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid
    )
    time.sleep(1)

    # Marker start attack
    send(marker_base/Marker(id=1, start=1, attack=1, type=b"toto"))

    # Fake attack
    send(IP(src=ip_list["EVIL"], dst=ip_list["UPF"])/UDP(dport=9999)/Raw(load="spoofed"))
    
    # Marker start normal
    send(marker_base/Marker(id=1, start=1, attack=0, type=b"tata"))
    
    # Fake normal
    send(IP(dst=ip_list["UPF"])/UDP(dport=9999)/Raw(load="spoofed"))

    # Marker stop attack
    send(marker_base/Marker(id=1, start=0, attack=1, type=b"toto"))
    
    # Marker stop normal
    send(marker_base/Marker(id=1, start=0, attack=0, type=b"tata"))

    # Stop tcpdump
    time.sleep(1)
    os.killpg(os.getpgid(tcpdump_proc.pid), signal.SIGINT)
    tcpdump_proc.wait()
    
    yield

def test_intervals():
    
    packets = rdpcap(CAPTURE_FILE)
    for is_attack in [True, False]:
        
        # 1 interval for benign and 1 for attacks
        intervals = _extract_intervals(packets,is_attack=is_attack)
        assert len(intervals) == 1
        
        for interval in intervals:
            
            # Intervals bounds are markers
            assert Marker in packets[interval.start] 
            assert Marker in packets[interval.end] 
            
            marker_start = packets[interval.start][Marker]
            marker_stop = packets[interval.end][Marker]
            
            # The first is a start and the second is an end
            assert marker_start.start
            assert not marker_stop.start
            
            # Markers are not mixed
            assert marker_start.id == marker_stop.id 
            assert marker_start.type == marker_stop.type 

def test_replace():
    
    ip_to_replace = ip_list["EVIL"]
    
    packets = rdpcap(CAPTURE_FILE)

    intervals = _extract_intervals(packets, is_attack=True)
    
    for interval in intervals:
                
        packets_to_process = packets[interval.start:interval.end+1]
        
        # Chech that initially they were packet with ip to be removed
        packet_containing_ip_to_remove = [packet for packet in packets_to_process if IP in packet and (packet[IP].src == ip_to_replace or packet[IP].dst == ip_to_replace)]
        assert len(packet_containing_ip_to_remove) > 0
        
        # Process and verify that no packet were removed
        processed_packets = _replace_addresses(packets_to_process, ip_to_replace)
        assert len(processed_packets) == len(packets_to_process) 
        
        # Check that the IP have been modified
        packet_containing_ip_to_remove = [packet for packet in processed_packets if IP in packet and (packet[IP].src == ip_to_replace or packet[IP].dst == ip_to_replace)]
        assert len(packet_containing_ip_to_remove) == 0
        
def test_process():
        
    packets = rdpcap(CAPTURE_FILE)    
    ip_to_replace = ip_list["EVIL"]
    processed_packets = process(packets, ip_to_replace)
    
    attack_intervals = _extract_intervals(packets, is_attack=True)
    benign_intervals = _extract_intervals(packets, is_attack=False)
    
    # The only missing packets are the markers
    number_of_markers = len(attack_intervals) * 2  # 2 attack markers
    number_of_markers += len(benign_intervals) * 2 # 2 benign markers
    number_of_markers *= 2                         # Each marker sent have a response
    assert len(processed_packets) == (len(packets) - number_of_markers)
    
    # Check that the IP have been modified
    packet_containing_ip_to_remove = [packet for packet in processed_packets if IP in packet and (packet[IP].src == ip_to_replace or packet[IP].dst == ip_to_replace)]
    assert len(packet_containing_ip_to_remove) == 0
    
def test_get_packet_by_type():
    
    packets = rdpcap(CAPTURE_FILE)    
    
    for is_attack in [True, False]:
        packets_by_type = get_packets_by_type(packets,is_attack=is_attack)
        assert len(packets_by_type) == 1   # benign and attack each supposed to have 1 type of pck
        
        for type,p_list in packets_by_type.items():
            
            assert len(p_list) > 0
            
            packets_with_evil_ip = [p for p in p_list if IP in p and (p[IP].src == ip_list["EVIL"] or p[IP].dst == ip_list["EVIL"])]
            assert len(packets_with_evil_ip) == 0
            
            packets_with_markers = [p for p in p_list if Marker in p]
            assert len(packets_with_markers) == 0
