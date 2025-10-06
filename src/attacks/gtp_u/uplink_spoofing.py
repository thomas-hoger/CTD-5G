from scapy.layers.inet import IP, ICMP, UDP
from scapy.all import Packet
from src.utils.protocols.pfcp.requests import PFCPRequest

from scapy.fields import ByteField, ShortField, IntField, ThreeBytesField
import struct


class GTPHeader(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP-C Header"
    fields_desc = [ 
        ByteField("flag", 0x34),
        ByteField("message_type", 0xff),
        ShortField("length", None),
        IntField("teid", 0x00000000),
        ThreeBytesField("padding", 0x000000),
        ByteField("next_header", 0x85),
        IntField("extension_header", 0x01100000)
    ]
    
    def post_build(self, p, pay):
        p += pay
        if self.length is None:
            # The message length field is calculated different in GTPv1 and GTPv2.  # noqa: E501
            # For GTPv1 it is defined as the rest of the packet following the mandatory 8-byte GTP header  # noqa: E501
            # For GTPv2 it is defined as the length of the message in bytes excluding the mandatory part of the GTP-C header (the first 4 bytes)  # noqa: E501
            tmp_len = len(p) - 4 if self.version == 2 else len(p) - 8
            p = p[:2] + struct.pack("!H", tmp_len) + p[4:]
        return p

def gtp_uplink_packet(src_addr:str, dst_addr:str, tunnel_dst_addr:str, ue_addr:str, teid:int, seq:int|None=None) -> Packet:

    if seq is None : 
        seq = PFCPRequest.random_seq()

    packet = (
        IP(src=src_addr, dst=dst_addr)
        / UDP(dport=2152, sport=2152)
        / GTPHeader(teid=teid, length=36)
        / IP(src=ue_addr, dst=tunnel_dst_addr)
        / ICMP(type=8, id=0x1234, seq=seq)
    )

    return packet
