from scapy.layers.inet import IP, UDP
from scapy.all import Packet

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

def pfcp_in_gtp_packet(src_addr:str, dst_addr:str, teid:int, pfcp_packet: Packet) -> Packet:
    
    gtp_packet = (
        IP(src=src_addr, dst=dst_addr)
        / UDP(sport=2152, dport=2152)
        / GTPHeader(teid=teid)
        / pfcp_packet
    )
    return gtp_packet
