
from scapy.packet import Packet, bind_layers
from scapy.fields import ShortField, XByteField, PacketListField, X3BytesField
from scapy.fields import BitField, XNBytesField, XBitField, ByteField

class NSSAI(Packet):
    name = "NSSAI"
    fields_desc = [
        XByteField("length", 4),
        XByteField("sst", None),
        X3BytesField("sd", None)
    ]
    def extract_padding(self, p):
        return "", p
    
class Requested_NSSAI(Packet):
    name = "Requested NSSAI"
    fields_desc = [
        XByteField("element_id", 0x2f),
        ByteField("length", None),
        PacketListField("nssai_list", [], NSSAI, length_from=lambda pkt: pkt.length)
    ] 
    def extract_padding(self, p):
        return "", p
    
class UE_Secu_Capabilities(Packet):
    name = "UE Secu Capabilities"
    fields_desc = [
        XByteField("element_id", 0x2e),
        XByteField("length", 0x4),
        XNBytesField("capabilities", 0xf0f0f0f0, 4)
    ]
    
class Registration_Mobile_Identity(Packet):
    name = "Mobile Identity"
    fields_desc = [
        ShortField("length", 13),
        BitField("supi_format", 0x0, 4),
        BitField("type_of_id", 0x0001, 4),
        X3BytesField("plmnID", 0x02f839), # mcc = 208 (02 + f8 -> 20 8f -> 208) mnc = 93 (39 -> 93)
        ShortField("routing_indicator", 0),
        XByteField("protection_scheme", 0),
        XByteField("home_network_pub_key", 0),
        XNBytesField("msin", 0x10, 5),
    ]
    
class NAS_Registration(Packet):
    name = "NAS Registration"
    fields_desc = [
        XBitField("key_identifier", 0x0111, 4),
        XBitField("registration_type", 0x1001, 4)
    ]

bind_layers(NAS_Registration, Registration_Mobile_Identity)
bind_layers(Registration_Mobile_Identity, UE_Secu_Capabilities)
bind_layers(UE_Secu_Capabilities, Requested_NSSAI)
