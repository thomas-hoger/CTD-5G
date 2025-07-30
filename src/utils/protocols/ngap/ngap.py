
from scapy.packet import Packet, bind_layers
from scapy.fields import ShortField, XByteField, StrLenField, PacketListField, X3BytesField, ConditionalField, PacketField
from scapy.layers.sctp import SCTPChunkData

from src.utils.protocols.nas.common import NAS

# Problem in the SCTP layer
if len(SCTPChunkData.fields_desc) >= 12:
    SCTPChunkData.fields_desc.pop(-1)
    
class NAS_IE(Packet):
    name = "NAS IE"
    fields_desc = [
        XByteField("length1", 0),
        XByteField("length2", 0),
        PacketField("NAS", NAS(), NAS),
    ]
    
class General_IE(Packet):
    name = "General IE"
    fields_desc = [
        XByteField("length", 0),
        StrLenField("value", b"", length_from=lambda pkt: pkt.length)
    ]
    def extract_padding(self, p):
        return "", p

class NGAP_IE(Packet):
    name = "NGAP IE"
    fields_desc = [
        ShortField("id", None),
        XByteField("criticality", None)
    ]
    
    def guess_payload_class(self, payload):
        if self.id == 38:
            return NAS_IE
        else:
            return General_IE
                   
class NGAP(Packet):
    name = "NGAP"
    fields_desc = [
        ShortField("procedureCode", None),
        XByteField("criticality", 0),
        XByteField("length", 0),
        ConditionalField(XByteField("asn_extra", 0), lambda pkt: pkt.length == 0x80),
        X3BytesField("count", 0),
        PacketListField("ie_list", [], NGAP_IE, count_from=lambda pkt: pkt.count)
    ]
    
bind_layers(SCTPChunkData, NGAP, proto_id=60)
