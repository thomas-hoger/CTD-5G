from scapy.all import Packet
from src.utils.protocols.nas.layer.common import NAS, NAS_Plaintext, NAS_Protected, Message_Type
from src.utils.protocols.nas.layer.register import NAS_Registration, Registration_Mobile_Identity, UE_Secu_Capabilities, Requested_NSSAI, NSSAI
from src.utils.protocols.nas.layer.deregister import NAS_Deregistration, Deregistration_Mobile_Identity

def nas_registration(msin:int, nssai_tuple_list:list[tuple[int,int]], plmnID:int) -> Packet:
    p = NAS(security=0x0) 
    p = p / NAS_Plaintext(message_type=Message_Type.RegistrationRequest.value)
    p = p / NAS_Registration() 
    p = p / Registration_Mobile_Identity(msin=msin, plmnID=plmnID)
    p = p / UE_Secu_Capabilities()
    
    nssai_packet_list = [NSSAI(sst=sst, sd=sd) for sst,sd in nssai_tuple_list]
    p = p / Requested_NSSAI(nssai_list=nssai_packet_list, length=len(nssai_packet_list)*5)
    return p

def nas_deregistration(tmsi:int, message_auth:int, sequence_number:int, plmnID:int) -> Packet:
    p = NAS(security=0x1) 
    p = p / NAS_Protected(message_auth=message_auth, seq_number=sequence_number)
    p = p / NAS_Plaintext(message_type=Message_Type.DeregistrationRequest.value)
    p = p / NAS_Deregistration() 
    p = p / Deregistration_Mobile_Identity(plmnID=plmnID, tmsi=tmsi)
    return p