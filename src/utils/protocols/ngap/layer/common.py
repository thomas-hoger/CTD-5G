
from scapy.packet import Packet, bind_layers
from scapy.fields import XByteField, ShortEnumField, LenField, PacketListField, X3BytesField, ConditionalField
from scapy.layers.sctp import SCTPChunkData
from enum import Enum

from src.utils.protocols.ngap.layer.ies import NAS_IE, PDU_SESSION_IE, General_IE_Value, UE_NGAP_IDs, FIVE_G_TMSI_IE, User_Location_IE

# Problem in the SCTP layer
if len(SCTPChunkData.fields_desc) >= 12:
    SCTPChunkData.fields_desc.pop(-1)

class NgapIEType(Enum):
    Cause = 15
    AMF_UE_NGAP_ID = 10
    FiveG_S_TMSI = 26
    NAS_PDU = 38
    RAN_UE_NGAP_ID = 85
    RRCEstablishmentCause = 90
    TAIListForPaging = 103
    UEContextRequest = 112
    UE_NGAP_IDs = 114
    UE_Paging_ID = 115
    UserLocationInformation = 121
    PDUSessionIDList = 133

class NgapProcedureCode(Enum):
    InitialUEMessage = 15
    Paging = 24
    UEContextReleaseCommand = 41
    UEContextReleaseRequest = 42

class NGAP_IE(Packet):
    name = "NGAP IE"
    fields_desc = [
        ShortEnumField("id", None, NgapIEType),
        XByteField("criticality", 0)
    ]
    
    def guess_payload_class(self, payload):
        
        match self.id:
            
            case NgapIEType.NAS_PDU.value:
                return NAS_IE
            
            case NgapIEType.PDUSessionIDList.value:
                return PDU_SESSION_IE
            
            case NgapIEType.UE_NGAP_IDs.value:
                return UE_NGAP_IDs
            
            case NgapIEType.UserLocationInformation.value:
                return User_Location_IE
            
            case NgapIEType.FiveG_S_TMSI.value:
                return FIVE_G_TMSI_IE
            
            case _:
                return General_IE_Value
                   
class NGAP(Packet):
    name = "NGAP"
    fields_desc = [
        ShortEnumField("procedureCode", None, NgapProcedureCode),
        XByteField("criticality", 0x0),
        XByteField("length", None),
        ConditionalField(XByteField("asn_extra", 0), lambda pkt: pkt.length == 0x80),
        X3BytesField("count", 0),
        PacketListField("ie_list", [], NGAP_IE, count_from=lambda pkt: pkt.count)
    ]
    
    def post_build(self, p, pay):
        if self.length is None:
            length = len(p) + len(pay) - 4
            p = p[:3] + (length).to_bytes(1) + p[4:]
        return p+pay
    
bind_layers(SCTPChunkData, NGAP, proto_id=60)
