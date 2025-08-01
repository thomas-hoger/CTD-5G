from scapy.packet import Packet
from scapy.fields import XBitField,PacketField, XByteField, X3BytesField, XNBytesField, LenField

class Deregistration_Mobile_Identity(Packet):
    name = "Mobile Identity"
    fields_desc = [
        LenField("length", 11),
        XByteField("type_of_id", 0xf2), # 5G-GUTI
        X3BytesField("plmnID", 0x02f839), # mcc = 208 (02 + f8 -> 20 8f -> 208) mnc = 93 (39 -> 93)
        XByteField("amf_region_id", 0xca), # 5G-GUTI
        XNBytesField("amf_set_id", 0xfe00, 2),
        XNBytesField("tmsi", 0x03c6, 4) 
    ]
    def extract_padding(self, p):
        return "", p

class NAS_Deregistration(Packet):
    name = "NAS Deregistration"
    fields_desc = [
        XBitField("secu_ctx_flag", 0x0, 1),   # Native secu
        XBitField("key_set_id", 0x000, 3), 
        XBitField("switch_off", 0x0, 1),      # Normal deregistration
        XBitField("re_registration", 0x0, 1), # Not required
        XBitField("access_type", 0x01, 2),    # 3GPP
        PacketField("mobile_identity", Deregistration_Mobile_Identity(), Deregistration_Mobile_Identity)
    ]
    def extract_padding(self, p):
        return "", p