
from scapy.packet import Packet, bind_layers
from scapy.fields import XByteField, ByteField, BitField, XNBytesField

from src.utils.protocols.nas.layer.registration import NAS_Registration
    
class NAS_Plaintext(Packet):
    name = "NAS Plaintext"
    fields_desc = [
        XByteField("message_type", None),
    ]

class NAS_Protected(Packet):
    name = "NAS Protected"
    fields_desc = [
        XNBytesField("message_auth", 0x10, 4),
        ByteField("seq_number", 0)
    ]
    
class NAS(Packet):
    name = "NAS"
    fields_desc = [
        BitField("epd", None, 2),       # Extended Protocol Discriminator
        BitField("spare", None, 6),       # 1/2 spare octet
        BitField("security", None, 4),    # 1/2 byte : header type
    ]
    
    def guess_payload_class(self, payload):
        if self.security == 0:
            return NAS_Plaintext
        else:
            return NAS_Protected
        
bind_layers(NAS_Plaintext, NAS_Registration, message_type=0x41)
bind_layers(NAS_Protected, NAS)