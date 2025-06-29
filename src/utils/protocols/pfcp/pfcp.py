from scapy.layers.inet import IP, UDP
from scapy.contrib import pfcp
from scapy.all import Packet

import random
import time

class PFCPRequest:
    
    max_teid = 0xffffffff
    max_seid = 0xffffffffffffffff
    
    def random_ue_address():
        return f"10.60.{random.randint(1,254)}.{random.randint(1,254)}"
    
    def random_seq():
        random.randint(1, 0xFFFFFF)

    def association_setup(src_addr:str, dst_addr:str, seq:int=random_seq()) -> Packet:

        # Build the complete packet
        return (
            IP(src=src_addr, dst=dst_addr) 
            / UDP(sport=8805, dport=8805) 
            / pfcp.PFCP(version=1, message_type=5, seid=0, S=0, seq=seq) # The first seid is always supposed to be 0 and is expected to be different from the 2nd one           
            / pfcp.PFCPAssociationSetupRequest(
                IE_list=[
                    pfcp.IE_NodeId(id_type=0, ipv4=src_addr),
                    pfcp.IE_RecoveryTimeStamp(timestamp=int(time.time()))
                ]
            )
        )

    def session_establishment(src_addr:str, dst_addr:str, ue_addr:str, seid:int, teid:int, seq:int=random_seq()) -> Packet:

        pdr = pfcp.IE_CreatePDR(
            IE_list=[
                pfcp.IE_PDR_Id(id=1),
                pfcp.IE_Precedence(precedence=255), # The priority of the packet. The closer it is to 1 the more important it is.
                pfcp.IE_PDI(
                    IE_list=[
                        pfcp.IE_SourceInterface(interface=1),
                        pfcp.IE_FTEID(TEID=teid, V4=1, ipv4=ue_addr),
                    ]
                ),
                pfcp.IE_FAR_Id(id=1),
            ]
        )
            
        far = pfcp.IE_CreateFAR(
            IE_list=[
                pfcp.IE_FAR_Id(id=1),
                pfcp.IE_ApplyAction(FORW=1),
                pfcp.IE_OuterHeaderCreation(
                    GTPUUDPIPV4=1, TEID=teid, ipv4=ue_addr, port=2152
                ),
            ]
        )
            
       # Build the complete packet
        return (
            IP(src=src_addr, dst=dst_addr)
            / UDP(sport=8805, dport=8805)
            / pfcp.PFCP(version=1, message_type=50, seid=0, S=1, seq=seq)  # S=1 is flag indicating that there will be a flag in the header 
            / pfcp.PFCPSessionEstablishmentRequest(
                IE_list=[
                    pfcp.IE_NodeId(id_type=0, ipv4=src_addr),
                    pfcp.IE_FSEID(seid=seid, v4=1, ipv4=src_addr),
                    pdr,
                    far
                ]
            )
        )
    
    def session_deletion(src_addr:str, dst_addr:str, seid:int, seq:int=random_seq()) -> Packet:
        
        # Build the complete packet
        return (
            IP(src=src_addr, dst=dst_addr)
            / UDP(sport=8805, dport=8805)
            / pfcp.PFCP(version=1, message_type=54, seid=seid, S=1, seq=seq)
            / pfcp.PFCPSessionDeletionRequest(
                IE_list=[
                    pfcp.IE_NodeId(id_type=0, ipv4=src_addr)
                ]
            )
        )

    def session_modification(src_addr:str, dst_addr:str, ue_addr:str, seid:int, teid:int, far_id:int, seq:int=random_seq(), actions:list[str]=["FORW"]) -> Packet:

        # We dynamically prepare the dictionary
        action_flags = {"FORW": 0, "DROP": 0, "BUFF": 0, "NOCP": 0, "DUPL": 0}
        for action in actions:
            if action.upper() in action_flags:
                action_flags[action] = 1
                
        # List of basic IE
        IE_list = [
            pfcp.IE_FAR_Id(id=far_id),
            pfcp.IE_ApplyAction(**action_flags)
        ]
        
        # Duplicate need additionnal IE
        if action_flags["DUPL"] == 1:
            IE_list.append(
                pfcp.IE_UpdateDuplicatingParameters(
                    IE_list=[
                        pfcp.IE_OuterHeaderCreation(
                            GTPUUDPIPV4=1, TEID=teid, ipv4=ue_addr, port=2152
                        ),
                    ]
                )
            )
            
        # Forward need additionnal IE
        if (action_flags["FORW"] == 1):
            IE_list.append(
                pfcp.IE_OuterHeaderCreation(
                    GTPUUDPIPV4=1, TEID=teid, ipv4=ue_addr, port=2152
                )
            )

        # Build the complete packet
        return (
            IP(src=src_addr, dst=dst_addr)
            / UDP(sport=8805, dport=8805)
            / pfcp.PFCP(version=1, message_type=52, S=1, seid=seid, seq=seq)
            / pfcp.PFCPSessionModificationRequest(
                IE_list=[
                    pfcp.IE_UpdateFAR(IE_list=IE_list)
                ]
            )
        )
