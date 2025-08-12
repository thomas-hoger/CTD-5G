from scapy.packet import Packet, bind_layers
from scapy.fields import XByteField, FieldLenField, XNBytesField, IntField, ShortField, X3BytesField, ByteField, StrLenField, PacketListField

from src.utils.protocols.nas.layer.common import NAS

class NAS_IE(Packet):
    name = "NAS IE"
    fields_desc = [
        ByteField("length1", None),
        ByteField("length2", None), # having 2 is not a mistake
    ]
    
class User_Location_IE(Packet):
    name = "User Location IE"
    fields_desc = [
        ByteField("length", 19), 
        XByteField("unknown_param1", 0x50),
        X3BytesField("plmnID1", 0x02f839), # mcc = 208 (02 + f8 -> 20 8f -> 208) mnc = 93 (39 -> 93)
        XNBytesField("nrCellID", 0x1, 4),
        XByteField("unknown_param2", 0x0),
        X3BytesField("plmnID2", 0x02f839),
        X3BytesField("tac", 0x1),
        XNBytesField("timeStamp", 0xec162cfc, 4) # (Jul  7, 2025 11:24:44 UTC)
    ]
    def extract_padding(self, p):
        return "", p
    
class FIVE_G_TMSI_IE(Packet):
    name = "5G TMSI IE"
    fields_desc = [
        ByteField("length", 7), 
        X3BytesField("AMF_SetID_Pointer", 0x3f8000),
        IntField("TMSI", None)
    ]
    def extract_padding(self, p):
        return "", p
    
class UE_NGAP_IDs(Packet):
    name = "UE NGAP ID pair"
    fields_desc = [
        ByteField("length", 6), 
        StrLenField("amf_ue_ngap_id", None, length_from=lambda pkt: pkt.length//2),
        StrLenField("ran_ue_ngap_id", None, length_from=lambda pkt: pkt.length//2),
    ]
    def extract_padding(self, p):
        return "", p
    
class PDU_SESSION_ID(Packet):
    name = "SESSION ID"
    fields_desc = [
        ShortField("id", None)
    ]
    def extract_padding(self, p):
        return "", p
    
class PDU_SESSION_IE(Packet):
    name = "PDU SESSION IE"
    fields_desc = [
        ByteField("length", 5),
        ByteField("count", 2),
        PacketListField("session_list", [], PDU_SESSION_ID, count_from=lambda pkt: pkt.count+1)
    ]
    def extract_padding(self, p):
        return "", p
    
class General_IE_Value(Packet):
    name = "General IE Value"
    fields_desc = [
        FieldLenField("length", None, fmt="B", length_of="value"),
        StrLenField("value", b'\x00\x00', length_from=lambda pkt: pkt.length)
    ]
    def extract_padding(self, p):
        return "", p
    
bind_layers(NAS_IE, NAS)