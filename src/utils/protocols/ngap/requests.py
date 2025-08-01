from src.utils.protocols.ngap.layer.common import NGAP, NgapIEType, NgapProcedureCode, NGAP_IE
from src.utils.protocols.ngap.layer.ies import General_IE_Value, PDU_SESSION_IE, UE_NGAP_IDs, User_Location_IE, FIVE_G_TMSI_IE

from src.utils.protocols.nas.layer.requests import nas_registration, nas_deregistration


from scapy.all import Packet

# AMF_ID and RAN_ID always seem to be equal
# There is not always 2 sessions
def ngap_ctx_release_request(amf_id:int, ran_id:int, session_id_list:list[int]) -> Packet:

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

def _int_to_bytes_dynamic(val:int) -> bytes:
    """Return the smallest bytes possible (with minimum 2 bytes) of the val conversion"""
    length = max(2, (val.bit_length() + 7) // 8 or 1)
    return val.to_bytes(length, byteorder='big')

# AMF_ID and RAN_ID seem to be equal at low value but differ at higher ones
# The number of bytes they take depend of their size with a min of 2
def ngap_ctx_release_command(amf_id:int, ran_id:int) -> Packet:
    
    # Procedure Type and IE List
    p = NGAP(
        procedureCode=NgapProcedureCode.UEContextReleaseCommand,
        criticality=0x0,
        count=0x2,
    )
    
    # Calculate the bytes of dynamic size
    amf_bytes = _int_to_bytes_dynamic(amf_id)
    ran_bytes = _int_to_bytes_dynamic(ran_id)

    # AMF and RAN IDs
    p = p / NGAP_IE(id=NgapIEType.UE_NGAP_IDs) / UE_NGAP_IDs(
        length = len(amf_bytes) + len(ran_bytes),
        amf_ue_ngap_id = amf_bytes,
        ran_ue_ngap_id = ran_bytes,
    )
    
    # Cause
    p = p / NGAP_IE(id=NgapIEType.Cause, criticality=0x1) / General_IE_Value()
    
    return p

def ngap_register(ran_id:int, msin:int, nssai_list:int=[(1,0x010203),(1,0x112233)], nrCellID:int=1, plmnID:int=0x02f839, tac:int=0x1) -> Packet:
    
    # Procedure Type and IE List
    p = NGAP(
        procedureCode=NgapProcedureCode.InitialUEMessage,
        criticality=0x1,
        count=0x5,
    )
    
    # RAN ID
    p = p / NGAP_IE(id=NgapIEType.RAN_UE_NGAP_ID) / General_IE_Value(value=(ran_id).to_bytes(2))
    
    # NAS Register
    p = p / NGAP_IE(id=NgapIEType.NAS_PDU) / nas_registration(msin, nssai_list, plmnID)
    
    # User Location
    p = p / NGAP_IE(id=NgapIEType.UserLocationInformation) / User_Location_IE(
        plmnID1 = plmnID,
        nrCellID = nrCellID,
        plmnID2 = plmnID,
        tac = tac    
    )
    
    # Constant
    p = p / NGAP_IE(id=NgapIEType.RRCEstablishmentCause, criticality=0x1) / General_IE_Value(value=b'\x18')
    
    # Constant
    p = p / NGAP_IE(id=NgapIEType.UEContextRequest, criticality=0x1) / General_IE_Value(value=b'\x00')
    
    return p

def ngap_deregister(ran_id:int, tmsi:int, message_auth:int, sequence_number=0, nrCellID:int=1, plmnID:int=0x02f839, tac:int=0x1) -> Packet:
    
    # Procedure Type and IE List
    p = NGAP(
        procedureCode=NgapProcedureCode.InitialUEMessage,
        criticality=0x1,
        count=0x6,
    )
    
    # RAN ID
    p = p / NGAP_IE(id=NgapIEType.RAN_UE_NGAP_ID) / General_IE_Value(value=(ran_id).to_bytes(2))
    
    # NAS Deregister
    p = p / NGAP_IE(id=NgapIEType.NAS_PDU) / nas_deregistration(tmsi, message_auth, sequence_number, plmnID)
    
    # User Location
    p = p / NGAP_IE(id=NgapIEType.UserLocationInformation) / User_Location_IE(
        plmnID1 = plmnID,
        nrCellID = nrCellID,
        plmnID2 = plmnID,
        tac = tac    
    )
    
    # Constant
    p = p / NGAP_IE(id=NgapIEType.RRCEstablishmentCause, criticality=0x1) / General_IE_Value(value=b'\x12')
    
    # TMSI
    p = p / NGAP_IE(id=NgapIEType.FiveG_S_TMSI) / FIVE_G_TMSI_IE(TMSI=tmsi)
    
    # Constant
    p = p / NGAP_IE(id=NgapIEType.UEContextRequest, criticality=0x1) / General_IE_Value(value=b'\x00')
    
    return p