from scapy.layers.inet import IP, UDP
from scapy.all import Packet, bind_layers
from scapy.fields import IntField, BitField, StrFixedLenField
from src.utils.common import ip_list

class Marker(Packet):
    name = "Marker"
    fields_desc = [
        IntField("id", 0),
        BitField("start", 0, 1),  # flag 1 bit
        BitField("attack", 0, 1),  # flag 1 bit
        BitField("padding", 0, 6), # to align on 1 byte
        StrFixedLenField("type", b"", length=20) 
    ]
    
bind_layers(UDP, Marker, dport=9999)
bind_layers(UDP, Marker, sport=9999)
    
marker_base = IP(dst=ip_list["UPF"])/UDP(dport=9999)