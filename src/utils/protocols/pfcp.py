from scapy.layers.inet import IP, UDP
from scapy.contrib import pfcp
import random
import time

class PFCPToolkit:
    
    seq = 1

    def new_seq(randomize=False):

        if randomize:
            seqNbr = random.randint(1, 0xFFFFFFFF)
            return seqNbr
        
        PFCPToolkit.seq += 1
        return PFCPToolkit.seq

    # FAR Operations

    def random_FAR() -> pfcp.IE_CreateFAR:
        """
        Create a random FAR (Forwarding Action Rule) for PFCP messages.

        Returns:
            IE_CreateFAR: The created FAR packet.
        """
        
        return pfcp.IE_CreateFAR(
            IE_list=[
                pfcp.IE_FAR_Id(id=random.randint(1, 255)),
                pfcp.IE_ApplyAction(FORW=1),
                pfcp.IE_OuterHeaderCreation(
                    GTPUUDPIPV4=1,
                    TEID=random.randint(1, 0xFFFFFFFF),
                    ipv4=".".join(str(random.randint(1, 254)) for _ in range(4)),
                    port=2152,
                ),
            ]
        )

    def update_FAR(far_id:int, action:pfcp.IE_ApplyAction = pfcp.IE_ApplyAction(FORW=1)):
        "Create a update FAR with a given action (default to FORWARD)"
        return pfcp.IE_UpdateFAR(
            IE_list=[
                pfcp.IE_FAR_Id(id=far_id), 
                action
            ]
        )

    # PFCP Message Building Functions

    def association_setup(src_addr:str, dst_addr:str) -> IP:

        seq = PFCPToolkit.new_seq()
        
        return (
            IP(src=src_addr, dst=dst_addr) 
            / UDP(sport=8805, dport=8805) 
            / pfcp.PFCP(version=1, message_type=5, seid=0, S=0, seq=seq)
            / pfcp.IE_NodeId(id_type=0, ipv4=src_addr)
            / pfcp.IE_RecoveryTimeStamp(timestamp=int(time.time()))
        )

    def session_establishment(src_addr:str, dst_addr:str, ue_addr=None, seid=0x1, teid=0x11111111, precedence=255, interface=1, FAR_number=1) -> IP:

        seq = PFCPToolkit.new_seq()

        pdr = pfcp.IE_CreatePDR(
            IE_list=[
                pfcp.IE_PDR_Id(id=1),
                pfcp.IE_Precedence(precedence=precedence),
                pfcp.IE_PDI(
                    IE_list=[
                        pfcp.IE_SourceInterface(interface=interface),
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
            
        pfcp_msg = (
            pfcp.PFCP(version=1, message_type=50, seid=0, S=1, seq=seq)
            / pfcp.IE_NodeId(id_type=0, ipv4=src_addr)
            / pfcp.IE_FSEID(seid=seid, v4=1, ipv4=src_addr)
            / pdr
            / far
        )

        for _ in range(FAR_number):
            pfcp_msg = pfcp_msg / PFCPToolkit.random_FAR()

        return (
            IP(src=src_addr, dst=dst_addr)
            / UDP(sport=8805, dport=8805)
            / pfcp_msg
        )

    def session_deletion(src_addr:str, dst_addr:str, seid=0x1) -> IP:
        
        seq = PFCPToolkit.new_seq()

        return (
            IP(src=src_addr, dst=dst_addr)
            / UDP(sport=8805, dport=8805)
            / pfcp.PFCP(version=1, message_type=54, seid=seid, S=1, seq=seq)
            / pfcp.IE_NodeId(id_type=0, ipv4=src_addr)
        )

    def session_modification(src_addr:str, dst_addr:str, tdst_addr:str, far_id:int, seid=0x1, actions:list[str]=["FORW"], teid=0x11111111) -> IP:

        seq = PFCPToolkit.new_seq()

        # On prépare dynamiquement le dictionnaire des flags
        action_flags = {"FORW": 0, "DROP": 0, "BUFF": 0, "NOCP": 0, "DUPL": 0}

        for action in actions:
            if action.upper() in action_flags:
                action_flags[action] = 1
        
        IE_list = [
            pfcp.IE_FAR_Id(id=far_id),
            pfcp.IE_ApplyAction(**action_flags)
        ]
        
        # Duplicate 
        if action_flags["DUPL"] == 1:
            IE_list.append(
                pfcp.IE_UpdateDuplicatingParameters(
                    IE_list=[
                        pfcp.IE_OuterHeaderCreation(
                            GTPUUDPIPV4=1, TEID=teid, ipv4=tdst_addr, port=2152
                        ),
                    ]
                )
            )
            
        # Forward
        elif (action_flags["FORW"] == 1 and action_flags["DUPL"] == 0 and tdst_addr is not None):
            IE_list.append(
                pfcp.IE_OuterHeaderCreation(
                    GTPUUDPIPV4=1, TEID=teid, ipv4=tdst_addr, port=2152
                )
            )

        return (
            IP(src=src_addr, dst=dst_addr)
            / UDP(sport=8805, dport=8805)
            / pfcp.PFCP(version=1, message_type=52, S=1, seid=seid, seq=seq)
            / pfcp.IE_UpdateFAR(IE_list=IE_list)
        )
