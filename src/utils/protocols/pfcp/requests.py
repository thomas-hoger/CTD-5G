from scapy.layers.inet import IP, UDP
from scapy.contrib import pfcp
from scapy.all import Packet

import json
import random

class PFCPRequest:
    
    with open('./src/utils/protocols/pfcp/templates.json', 'r') as f:
        templates = json.load(f)
    
    # if the value is too high it can cause -> panic: runtime error: index out of range
    max_teid = 0xffff
    max_seid = 0xffff
    
    def random_ue_address():
        return f"10.60.{random.randint(1,254)}.{random.randint(1,254)}"
    
    def random_seq():
        return random.randint(1, 0xffff)

    def session_establishment(src_addr:str, dst_addr:str, ue_addr:str, seid:int, teid:int, seq:int|None=None) -> Packet:
        
        if seq is None : 
            seq = PFCPRequest.random_seq()

        pfcp_bytes   = bytes.fromhex(PFCPRequest.templates["establishment"])
        pfcp_message = pfcp.PFCP(pfcp_bytes)
        
        pfcp_message.seq = seq
        
        # F-SEID IE
        pfcp_message["PFCPSessionEstablishmentRequest"].IE_list[1].ipv4 = src_addr
        pfcp_message["PFCPSessionEstablishmentRequest"].IE_list[1].seid = seid

        # PDR -> PDI -> FTEID (for PDR 1 and 3)
        pfcp_message["PFCPSessionEstablishmentRequest"].IE_list[2].IE_list[2].IE_list[1].TEID = teid
        pfcp_message["PFCPSessionEstablishmentRequest"].IE_list[2].IE_list[2].IE_list[1].ipv4 = dst_addr
        pfcp_message["PFCPSessionEstablishmentRequest"].IE_list[4].IE_list[2].IE_list[1].TEID = teid
        pfcp_message["PFCPSessionEstablishmentRequest"].IE_list[4].IE_list[2].IE_list[1].ipv4 = dst_addr

        # PDR -> PDI -> UE IP Address (for each PDR)
        pfcp_message["PFCPSessionEstablishmentRequest"].IE_list[2].IE_list[2].IE_list[3].ipv4 = ue_addr
        pfcp_message["PFCPSessionEstablishmentRequest"].IE_list[4].IE_list[2].IE_list[3].ipv4 = ue_addr
        pfcp_message["PFCPSessionEstablishmentRequest"].IE_list[3].IE_list[2].IE_list[2].ipv4 = ue_addr
        pfcp_message["PFCPSessionEstablishmentRequest"].IE_list[5].IE_list[2].IE_list[2].ipv4 = ue_addr

       # Build the complete packet
        return (
            IP(src=src_addr, dst=dst_addr)
            / UDP(sport=8805, dport=8805)
            / pfcp_message
        )
    
    def session_deletion(src_addr:str, dst_addr:str, seid:int, seq:int|None=None) -> Packet:
        
        if seq is None : 
            seq = PFCPRequest.random_seq()
            
        pfcp_bytes   = bytes.fromhex(PFCPRequest.templates["deletion"])
        pfcp_message = pfcp.PFCP(pfcp_bytes)
        
        pfcp_message.seq = seq
        pfcp_message.seid = seid
        
        # Build the complete packet
        return (
            IP(src=src_addr, dst=dst_addr)
            / UDP(sport=8805, dport=8805)
            / pfcp_message
        )
        
    def seid_fuzzing(src_addr:str, dst_addr:str, ue_addr:str, seid:int, seq:int|None=None) -> Packet:
        
        if seq is None : 
            seq = PFCPRequest.random_seq()
            
        pfcp_bytes   = bytes.fromhex(PFCPRequest.templates["modification"])
        pfcp_message = pfcp.PFCP(pfcp_bytes)
        
        pfcp_message.seq = seq
        pfcp_message.seid = seid
        
        pfcp_message["PFCPSessionModificationRequest"].IE_list[0].seid = seid
        
        pfcp_message["PFCPSessionModificationRequest"].IE_list[1].IE_list[2].IE_list[2].ipv4 = ue_addr
        pfcp_message["PFCPSessionModificationRequest"].IE_list[2].IE_list[2].IE_list[2].ipv4 = ue_addr
        
        # Build the complete packet
        return (
            IP(src=src_addr, dst=dst_addr)
            / UDP(sport=8805, dport=8805)
            / pfcp_message
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
