
from scapy.packet import Packet, bind_layers
from scapy.fields import XByteField, ByteField, BitField, XNBytesField, XByteEnumField
from enum import Enum

from src.utils.protocols.nas.layer.register import NAS_Registration
from src.utils.protocols.nas.layer.deregister import NAS_Deregistration
    
class Message_Type(Enum):
    RegistrationRequest = 0x41
    DeregistrationRequest = 0x45
    
class NAS_Plaintext(Packet):
    name = "NAS Plaintext"
    fields_desc = [
        XByteEnumField("message_type", None, Message_Type)    
    ]

class NAS_Protected(Packet):
    name = "NAS Protected"
    fields_desc = [
        XNBytesField("message_auth", None, 4),
        ByteField("seq_number", 0)
    ]
    
class NAS(Packet):
    name = "NAS"
    fields_desc = [
        XByteField("epd", 0x7e),       # Extended Protocol Discriminator
        BitField("spare", 0x0, 4),     # 1/2 spare octet
        BitField("security", None, 4), # 1/2 byte : header type
    ]
    
    def guess_payload_class(self, payload):
        if self.security == 0:
            return NAS_Plaintext
        else:
            return NAS_Protected
        
bind_layers(NAS_Plaintext, NAS_Registration, message_type=Message_Type.RegistrationRequest.value)
bind_layers(NAS_Plaintext, NAS_Deregistration, message_type=Message_Type.DeregistrationRequest.value)
bind_layers(NAS_Protected, NAS)