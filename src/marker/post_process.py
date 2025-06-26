from src.marker.generation import AttackMarker
import random
from scapy.all import rdpcap
from scapy.plist import PacketList

def extract_intervals(packets: PacketList) -> dict[str,tuple[int,int]]:
    intervals = {}  # {id: (start_idx, end_idx)}
    open_markers = {}

    for i, pkt in enumerate(packets):
        
        # Find the AttackMarker
        if AttackMarker in pkt:
            marker = pkt[AttackMarker]
            marker_id = marker.id
            
            # We save the position of the first marker
            if marker.start == 1:
                open_markers[marker_id] = i
                
            # If we find the second we create a tuple with the start and end position
            elif marker.start == 0 and marker_id in open_markers:
                start = open_markers.pop(marker.id)
                intervals[marker.id] = (start, i)

    return intervals

def replace_addresses(packets: PacketList, ip_to_replace:str) -> PacketList:
    
    interval = extract_intervals(packets)
    ip_to_spoof = f"10.200.100.{random.randint(1,254)}" 

    for pkt in packets:
        
        if AttackMarker in pkt:
            # remove
            pass
        
        else : 
            pass
            # if ip src = ip_to_replace :
                # pkt[IP].src = ip_to_spoof
                # pkt[ETHER].src = mac_to_spoof
            # if ip_dst = ip_to_replace

    return packets[1:-1] # remove the two markers
          
  
# packets = rdpcap(file)
# packets.sort(key=lambda p: p.time)