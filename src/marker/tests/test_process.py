from src.marker.post_process import _extract_intervals, _replace_addresses, process
from src.marker.generation import Marker
from src.utils.common import ip_list
from scapy.layers.inet import IP, Ether

from scapy.all import rdpcap

def test_intervals():
    
    packets = rdpcap("./src/marker/tests/example.pcap")
    for is_attack in [True, False]:
        
        intervals = _extract_intervals(packets,is_attack=is_attack)
        
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
            assert marker_start.attack_type == marker_stop.attack_type 

def test_replace():
    
    ip_to_replace = ip_list["EVIL"]
    
    packets = rdpcap("./src/marker/tests/example.pcap")
    
    for is_attack in [True, False]:
        intervals = _extract_intervals(packets, is_attack=is_attack)
        
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
    
    ip_to_replace = ip_list["EVIL"]
    
    packets = rdpcap("./src/marker/tests/example.pcap")    
    
    for packet in packets:
        if Ether in packet and packet[Ether].dst == "00:11:22:33:44:55":
            print(packet)
    assert False
    
    processed_packets = process(packets, ip_to_replace)
    
    attack_intervals = _extract_intervals(packets, is_attack=True)
    benign_intervals = _extract_intervals(packets, is_attack=False)
    
    # The only missing packets are the markers
    number_of_markers = len(attack_intervals) * 2 + len(benign_intervals) * 2
    assert len(processed_packets) == (len(packets) - number_of_markers)
    
    # Check that the IP have been modified
    packet_containing_ip_to_remove = [packet for packet in processed_packets if IP in packet and (packet[IP].src == ip_to_replace or packet[IP].dst == ip_to_replace)]
    for p in packet_containing_ip_to_remove[:5]:
        print(p)
    assert len(packet_containing_ip_to_remove) == 0
    