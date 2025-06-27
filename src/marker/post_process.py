from src.marker.generation import AttackMarker
import random
# from scapy.all import rdpcap, Packet
from scapy.plist import PacketList
from scapy.layers.inet import IP, Ether

def extract_intervals(packets: PacketList) -> dict[str,tuple[int,int]]:
    """
    Extracts intervals from a list of packets based on AttackMarker start and end markers.
    Args:
        packets (PacketList): List of packets to process.
    Returns:
        dict[str, tuple[int, int]]: Dictionary mapping marker IDs to (start_idx, end_idx) tuples indicating the interval positions in the packet list.
    """
    intervals = {}  # {id: (start_idx, end_idx)}
    open_markers = {}

    for i, pkt in enumerate(packets):
        
        # Find the AttackMarker
        if AttackMarker in pkt:
            marker = pkt[AttackMarker]
            marker_id = marker.id
            
            # We save the position of the first marker
            if marker.start == 1 and marker_id not in open_markers:
                open_markers[marker_id] = i
                
            # If we find the second we create a tuple with the start and end position
            elif marker.start == 0 and marker_id in open_markers:
                start = open_markers[marker.id]
                intervals[marker.id] = (start, i)

    return intervals

def replace_addresses(packets: PacketList, ip_to_replace:str) -> PacketList:
    """
    Replaces the source and destination IP and MAC addresses in packets matching a given IP.
    Args:
        packets (PacketList): List of packets to process.
        ip_to_replace (str): IP address to be replaced.
    Returns:
        PacketList: New PacketList with updated addresses.
    """
    
    ip_to_spoof  = f"10.200.100.{random.randint(1,254)}" 
    mac_to_spoof = ':'.join(f'{random.randint(0, 255):02x}' for _ in range(6))
    new_packets  = []
    
    for pkt in packets:
        
        if AttackMarker not in pkt:
        
            if IP in pkt :
        
                if pkt[IP].src == ip_to_replace :
                    pkt[IP].src = ip_to_spoof
                    
                    if Ether in pkt : 
                        pkt[Ether].src = mac_to_spoof
                    
                if pkt[IP].dst == ip_to_replace :
                    pkt[IP].dst = ip_to_spoof
                    
                    if Ether in pkt : 
                        pkt[Ether].dst = mac_to_spoof
                
            new_packets.append(pkt)

    return PacketList(new_packets)
          
def process(packets: PacketList, ip_to_replace:str) -> PacketList:
    """
    Processes a list of packets by replacing IP addresses within specified intervals.
    Args:
        packets (PacketList): The list of packets to process.
        ip_to_replace (str): The IP address to use for replacement within intervals.
    Returns:
        PacketList: The processed list of packets with addresses replaced in specified intervals.
    """
    
    intervals = extract_intervals(packets)
    intervals = dict(sorted(intervals.items(), key=lambda x: x[1][0]))
    
    processed_packets = PacketList([])

    last_end = 0

    for _, (start, end) in intervals.items():
        
        # Packets outside last_end et start are not modified
        # Stops before the start marker
        processed_packets += packets[last_end:start]

        # Packets between last_end et start are processed
        # Bother start and end marker packet are comprised in the input packets
        # Yet the marker packets are also removed by replace_addresses
        processed = replace_addresses(packets[start:end+1], ip_to_replace)
        processed_packets += processed

        last_end = end + 1

    # Add the packet after the last interval
    processed_packets += packets[last_end:]
    
    return processed_packets