from scapy.layers.inet import IP, UDP
from scapy.contrib.gtp import GTP_U_Header

from src.utils.protocols.pfcp import PFCPToolkit

import random

class PFCP_in_GTP():

    seq = 1

    def new_seq(rand=False):
        if rand:
            seq = random.randint(0, 0xFFFF)
        else:
            PFCP_in_GTP.seq += 1
            seq = PFCP_in_GTP.seq
        return seq

    def pfcp_in_gtp_packet(src_addr:str, dest_addr:str, teid:int, ue_addr:str):
        
        pfcp_packet = PFCPToolkit.association_setup(dest_addr, ue_addr)

        gtp_packet = (
            IP(src=src_addr, dst=dest_addr)
            / UDP(sport=2152, dport=2152)
            / GTP_U_Header(teid=teid)
            / pfcp_packet
        )
        return gtp_packet
