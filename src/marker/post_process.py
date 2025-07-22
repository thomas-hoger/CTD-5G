from src.marker.generation import Marker
from src.utils.common import ip_list

import random
# from scapy.all import rdpcap, Packet

from scapy.plist import PacketList
from scapy.layers.inet import IP, Ether

from dataclasses import dataclass

@dataclass
class Interval:
    start: int
    end: int | None
    id: int
    type: str

    def __contains__(self, value: int) -> bool:
        return self.end is not None and (self.start <= value <= self.end)

def _find_interval(intervals: list[Interval], marker_id:int, marker_type:str) -> Interval | None:
    """
    Finds and returns the first Interval from a list that matches the given marker_id and marker_type.

    Args:
        intervals (list[Interval]): List of Interval objects to search.
        marker_id (int): The ID of the marker to match.
        marker_type (str): The type of the marker to match.

    Returns:
        Interval | None: The matching Interval if found, otherwise None.
    """
    for interval in intervals :
        if interval.id == marker_id and interval.type == marker_type:
            return interval

def _extract_intervals(packets: PacketList, is_attack=True) -> list[Interval]:
    """
    Extracts intervals from a list of packets based on marker start/stop events.
    Args:
        packets (PacketList): List of packets to process.
        is_attack (bool, optional): If True, extracts attack intervals; otherwise, extracts non-attack intervals. Defaults to True.
    Returns:
        list[Interval]: List of extracted intervals with start and end indices, marker id, and type.
    """

    intervals = []

    for i, pkt in enumerate(packets):
        
        # Find markers
        if Marker in pkt:
            
            # If marker is of the right nature
            marker:Marker = pkt[Marker]
            if bool(marker.attack) == is_attack:
            
                # If the marker is a start and don't already existe we create it
                if marker.start == 1:
                    interval = _find_interval(intervals, marker.id, marker.type)
                    if not interval :
                        intervals.append(
                            Interval(i,None,marker.id,marker.type)
                        )
                        
                # If the marker is a stop we modify its end index
                else :
                    interval = _find_interval(intervals, marker.id, marker.type)
                    if interval:
                        interval.end = i

    return intervals

def _replace_addresses(packets: PacketList, ip_to_replace:str) -> PacketList:
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
          
def _remove_markers(packets: PacketList) -> PacketList:
    return PacketList([p for p in packets if Marker not in p])

def _filter_attacks(packets: PacketList) -> PacketList:
    return [p for p in packets if IP in p and (p[IP].src == ip_list['EVIL'] or p[IP].dst == ip_list['EVIL'])]

def _filter_benigns(packets: PacketList) -> PacketList:
    return [p for p in packets if IP not in p or (p[IP].src != ip_list['EVIL'] or p[IP].dst != ip_list['EVIL'])]

def get_packets_by_type(packets: PacketList, is_attack=True) -> dict[str:PacketList]:
    
    packets_by_type = {} 
    intervals       = _extract_intervals(packets, is_attack)
    for interval in intervals:
        
        packet_interval = PacketList(packets[interval.start:interval.end])
            
        # if is attack, replace the ip and get only the attacks
        if is_attack:
            packet_interval = _filter_attacks(packet_interval) 
            packet_interval =  _replace_addresses(packet_interval, ip_list["EVIL"])
            
        # if it is benign, dont take the attacks
        else :    
            packet_interval = _filter_benigns(packet_interval) 
        
        # for all the packets in the interval, remove markers
        packet_interval = _remove_markers(packet_interval)
        
        # add to a dict and create it if it does not exist
        if interval.type not in packets_by_type:
            packets_by_type[interval.type] = PacketList([])
        packets_by_type[interval.type] += packet_interval
        
    return packets_by_type

def process(packets: PacketList, ip_to_replace:str) -> PacketList:
    """
    Processes a PacketList by replacing IP addresses within attack intervals and removing marker packets.
    Args:
        packets (PacketList): The list of packets to process.
        ip_to_replace (str): The IP address to use for replacement within attack intervals.
    Returns:
        PacketList: The processed list of packets with addresses replaced in attack intervals and markers removed.
    """
    
    attack_intervals  = _extract_intervals(packets, is_attack=True)
    processed_packets = PacketList([])

    last_end = 0

    for interval in attack_intervals:
        
        # Packets outside last_end et start are not modified
        # Stops before the start marker
        processed_packets += packets[last_end:interval.start]

        # Packets between last_end et start are processed
        # Bother start and end marker packet are comprised in the input packets
        interval_end = interval.end+1 if interval.end is not None else len(packets)
        processed = _replace_addresses(packets[interval.start:interval_end], ip_to_replace)
        processed_packets += processed

        last_end = interval_end

    # Add the packet after the last interval
    processed_packets += packets[last_end:]
    processed_packets = _remove_markers(processed_packets)
    
    return processed_packets