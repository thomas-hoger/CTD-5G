from scapy.packet import Packet
from scapy.fields import XByteField, FieldLenField, NBytesField, ShortField, X3BytesField, LenField, StrLenField, PacketListField, PacketField

from src.utils.protocols.nas.layer.common import NAS

class NAS_IE(Packet):
    name = "NAS IE"
    fields_desc = [
        LenField("length1", None, fmt="B"),
        LenField("length2", None, fmt="B"), # having 2 is not a mistake
        PacketField("NAS", NAS(), NAS),
    ]
    
class User_Location_IE(Packet):
    name = "User Location IE"
    fields_desc = [
        LenField("length", None, fmt="B"), 
        XByteField("unknown_param", 0x50),
        X3BytesField("plmnID1", 0x02f839), # mcc = 208 (02 + f8 -> 20 8f -> 208) mnc = 93 (39 -> 93)
        NBytesField("nrCellID", 0x1, 4),
        X3BytesField("plmnID2", 0x02f839),
        X3BytesField("tac", 0x1),
        NBytesField("timeStamp", 0xec162cfc, 4) # (Jul  7, 2025 11:24:44 UTC)
    ]
    
class FIVE_G_TMSI_IE(Packet):
    name = "5G TMSI IE"
    fields_desc = [
        LenField("length", None, fmt="B"), 
        X3BytesField("AMF_SetID_Pointer", 0x3f8000),
        NBytesField("TMSI", None, 4)
    ]
    
class UE_NGAP_IDs(Packet):
    name = "UE NGAP ID pair"
    fields_desc = [
        LenField("length", None, fmt="B"),
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
        LenField("length", None, fmt="B"),
        XByteField("count", 0),
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