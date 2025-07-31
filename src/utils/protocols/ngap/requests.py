from src.utils.protocols.ngap.layer.common import NGAP, NgapIEType, NgapProcedureCode, NGAP_IE
from src.utils.protocols.ngap.layer.ies import General_IE_Value, PDU_SESSION_IE

from scapy.all import Packet

def ngap_ctx_release(amf_id:int, ran_id:int, session_id_list:list[int]) -> Packet:

    # Procedure Type and IE List
    p = NGAP(
        procedureCode=NgapProcedureCode.UEContextReleaseRequest,
        criticality=0x40,
        count=0x4,
    )

    # AMF and RAN IDs
    p = p / NGAP_IE(id=NgapIEType.AMF_UE_NGAP_ID) / General_IE_Value(value=(amf_id).to_bytes(2))
    p = p / NGAP_IE(id=NgapIEType.RAN_UE_NGAP_ID) / General_IE_Value(value=(ran_id).to_bytes(2))
    
    # PDU Session IDs
    session_id_list_bytes = [(session_id).to_bytes(2) for session_id in session_id_list]
    p = p / NGAP_IE(id=NgapIEType.PDUSessionIDList) / PDU_SESSION_IE(count=1, session_list=session_id_list_bytes)
    
    # Cause
    p = p / NGAP_IE(id=NgapIEType.Cause, criticality=0x40) / General_IE_Value()
    
    return p

p = ngap_ctx_release(amf_id=1, ran_id=1, session_id_list=[1,2])
p.show2()