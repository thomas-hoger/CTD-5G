from scapy.packet import Packet
from scapy.fields import XByteField, FieldLenField,ShortField, LenField, StrLenField, PacketListField, PacketField

from src.utils.protocols.nas.layer.common import NAS

class NAS_IE(Packet):
    name = "NAS IE"
    fields_desc = [
        LenField("length1", None, fmt="B"),
        LenField("length2", None, fmt="B"), # having 2 is not a mistake
        PacketField("NAS", NAS(), NAS),
    ]
    
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