from scapy.all import Packet
from src.utils.protocols.nas.layer.common import NAS, NAS_Plaintext, NAS_Protected, Message_Type
from src.utils.protocols.nas.layer.register import NAS_Registration, Registration_Mobile_Identity, UE_Secu_Capabilities, Requested_NSSAI, NSSAI
from src.utils.protocols.nas.layer.deregister import NAS_Deregistration, Deregistration_Mobile_Identity

def nas_registration(msin:int, nssai_list:list[tuple[int,int]], plmnID:int) -> Packet:
    p = NAS(security=0x0) 
    p = p / NAS_Plaintext(message_type=Message_Type.RegistrationRequest)
    p = p / NAS_Registration() 
    p = p / Registration_Mobile_Identity(msin=msin, plmnID=plmnID)
    p = p / UE_Secu_Capabilities()
    p = p / Requested_NSSAI()
    
    for sst,sd in nssai_list:
        p = p / NSSAI(sst=sst, sd=sd)
        
    return p

def nas_deregistration(tmsi:int, message_auth:int, sequence_number:int, plmnID:int) -> Packet:
    p = NAS(security=0x1) 
    p = p / NAS_Protected(message_auth=message_auth, seq_number=sequence_number)
    p = p / NAS_Plaintext(message_type=Message_Type.DeregistrationRequest)
    p = p / NAS_Deregistration() 
    p = p / Deregistration_Mobile_Identity(plmnID=plmnID, tmsi=tmsi)
    return p