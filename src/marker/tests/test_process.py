from src.marker.post_process import extract_intervals, replace_addresses, process
from src.marker.generation import AttackMarker
from src.utils.common import ip_list
from scapy.layers.inet import IP

from scapy.all import rdpcap

def test_intervals():
    
    packets = rdpcap("./src/marker/tests/example.pcap")
    intervals = extract_intervals(packets)
    
    for start, stop in intervals.values():
        
        # Intervals bounds are markers
        assert AttackMarker in packets[start] 
        assert AttackMarker in packets[stop] 
        
        marker_start = packets[start][AttackMarker]
        marker_stop = packets[stop][AttackMarker]
        
        # The first is a start and the second is an end
        assert marker_start.start
        assert not marker_stop.start
        
        # Markers are not mixed
        assert marker_start.id == marker_stop.id 
        assert marker_start.attack_type == marker_stop.attack_type 

def test_replace():
    
    ip_to_replace = ip_list["EVIL"]
    
    packets = rdpcap("./src/marker/tests/example.pcap")
    intervals = extract_intervals(packets)
    
    for (start, stop) in intervals.values():
                
        packets_to_process = packets[start:stop+1]
        
        # Chech that initially they were packet with ip to be removed
        packet_containing_ip_to_remove = [packet for packet in packets_to_process if IP in packet and (packet[IP].src == ip_to_replace or packet[IP].dst == ip_to_replace)]
        assert len(packet_containing_ip_to_remove) > 0
        
        # Process and verify that the marker have been removed
        processed_packets = replace_addresses(packets_to_process, ip_to_replace)
        assert len(processed_packets) <len(packets_to_process) 
        
        # Check that the IP have been modified
        packet_containing_ip_to_remove = [packet for packet in processed_packets if IP in packet and (packet[IP].src == ip_to_replace or packet[IP].dst == ip_to_replace)]
        assert len(packet_containing_ip_to_remove) == 0
        
def test_process():
    
    ip_to_replace = ip_list["EVIL"]
    
    packets = rdpcap("./src/marker/tests/example.pcap")    
    processed_packets = process(packets,ip_to_replace)
    
    # The only missing packets are the markers
    assert len(processed_packets) < len(packets) 
    
    # Check that the IP have been modified
    packet_containing_ip_to_remove = [packet for packet in processed_packets if IP in packet and (packet[IP].src == ip_to_replace or packet[IP].dst == ip_to_replace)]
    assert len(packet_containing_ip_to_remove) == 0
    