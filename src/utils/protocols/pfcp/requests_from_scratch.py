from scapy.layers.inet import IP, UDP
from scapy.contrib import pfcp
from scapy.all import Packet

import random
import time

class PFCPRequest:
    
    # if the value is too high it can cause -> panic: runtime error: index out of range
    max_teid = 0xffff
    max_seid = 0xffff
    
    def random_ue_address():
        return f"10.60.{random.randint(1,254)}.{random.randint(1,254)}"
    
    def random_seq():
        return random.randint(1, 0xffff)
    
    def association_setup(src_addr:str, dst_addr:str, seq:int|None=None) -> Packet:

        if seq is None : 
            seq = PFCPRequest.random_seq()
            
        message_template = "2005001e3f39a600003c000902076f61692d736d6600600004eca4c4580059000103"
        message_bytes = bytes.fromhex(message_template)
            
        # Build the complete packet
        return (
            IP(src=src_addr, dst=dst_addr) 
            / UDP(sport=8805, dport=8805) 
            / pfcp.PFCP(message_bytes) # The first seid is always supposed to be 0 and is expected to be different from the 2nd one           
        )

    def session_establishment(src_addr:str, dst_addr:str, ue_addr:str, seid:int, teid:int, seq:int|None=None) -> Packet:
        
        if seq is None : 
            seq = PFCPRequest.random_seq()

        pdr = pfcp.IE_CreatePDR(
            IE_list=[
                pfcp.IE_PDR_Id(id=1),
                pfcp.IE_Precedence(precedence=255), # The priority of the packet. The closer it is to 1 the more important it is.
                pfcp.IE_PDI(
                    IE_list=[
                        pfcp.IE_SourceInterface(interface=1),
                        pfcp.IE_FTEID(TEID=teid, V4=1, ipv4=ue_addr),
                        pfcp.IE_NetworkInstance(instance="access.oai.org"),
                        pfcp.IE_UE_IP_Address(V4=1, ipv4=ue_addr),
                        pfcp.IE_SDF_Filter(FD=1,flow_description="permit out ip from any to assigned"),
                        pfcp.IE_QFI(QFI=0x1)
                    ]
                ),
                pfcp.IE_OuterHeaderRemoval(header=0),
                pfcp.IE_FAR_Id(id=1),
                pfcp.IE_URR_Id(id=1),
            ]
        )
            
        far = pfcp.IE_CreateFAR(
            IE_list=[
                pfcp.IE_FAR_Id(id=1),
                pfcp.IE_ApplyAction(FORW=1),
                pfcp.IE_ForwardingParameters(
                    IE_list=[
                        pfcp.IE_DestinationInterface(interface=1),
                        pfcp.IE_NetworkInstance(instance="internet.oai.org")
                    ]
                )
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
    
    def session_deletion(src_addr:str, dst_addr:str, seid:int, seq:int|None=None) -> Packet:
        
        if seq is None : 
            seq = PFCPRequest.random_seq()
        
        # Build the complete packet
        return (
            IP(src=src_addr, dst=dst_addr)
            / UDP(sport=8805, dport=8805)
            / pfcp.PFCP(version=1, message_type=54, seid=seid, S=1, seq=seq)
            / pfcp.PFCPSessionDeletionRequest(IE_list=[])
        )

    def session_modification(src_addr:str, dst_addr:str, ue_addr:str, seid:int, teid:int, far_id:int, seq:int|None=None, actions:list[str]=["FORW"]) -> Packet:

        if seq is None : 
            seq = PFCPRequest.random_seq()

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
