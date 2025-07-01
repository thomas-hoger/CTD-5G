from scapy.layers.inet import Ether
from scapy.all import Packet, bind_layers
from scapy.fields import IntField, BitField, StrFixedLenField

class Marker(Packet):
    name = "Marker"
    fields_desc = [
        IntField("id", 0),
        BitField("start", 0, 1),  # flag 1 bit
        BitField("attack", 0, 1),  # flag 1 bit
        BitField("padding", 0, 6), # to align on 1 byte
        StrFixedLenField("type", b"", length=20) 
    ]
    
CUSTOM_ETHER_TYPE = 0x88B5
bind_layers(Ether, Marker, type=CUSTOM_ETHER_TYPE)
marker_base = Ether(dst="00:11:22:33:44:55", type=CUSTOM_ETHER_TYPE)