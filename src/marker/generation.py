from scapy.layers.inet import IP, UDP
from scapy.all import Packet, bind_layers
from scapy.fields import IntField, BitField, StrFixedLenField

from src.utils.common import ip_list

class AttackMarker(Packet):
    name = "AttackMarker"
    fields_desc = [
        IntField("id", 0),
        BitField("start", 0, 1),  # flag 1 bit
        BitField("padding", 0, 7), # to align on 1 byte
        StrFixedLenField("attack_type", b"", length=20) 
    ]
    
bind_layers(UDP, AttackMarker, sport=9999)
    
# Need to put an IP that exists, else it would do a broadcast
marker_base = IP(dst=ip_list["UPF"]) / UDP(sport=9999, dport=9999)