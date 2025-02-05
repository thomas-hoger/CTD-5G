from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, BitField, FieldLenField, StrLenField, ByteEnumField

# Enum simplifiés
nas_msg_types = {
    0xc1: "PDU Session Establishment Request",
    # ajouter d'autres si besoin
}

# IE: Integrity protection maximum data rate
class NASMaxDataRate(Packet):
    name = "Integrity Protection Max Data Rate"
    fields_desc = [
        ByteField("ul", 255),
        ByteField("dl", 255)
    ]

# IE: PDU session type
class NASPDUSessionType(Packet):
    name = "PDU Session Type"
    fields_desc = [
        BitField("eid", 0x9, 4),
        BitField("type", 0x1, 4)
    ]

# IE: SSC mode
class NASSSCMode(Packet):
    name = "SSC Mode"
    fields_desc = [
        BitField("eid", 0xA, 4),
        BitField("mode", 0x1, 4)
    ]

# IE: 5GSM Capability
class NAS5GSMCapability(Packet):
    name = "5GSM Capability"
    fields_desc = [
        ByteField("eid", 0x28),
        ByteField("length", 1),
        ByteField("flags", 0x00)
    ]

# IE: Extended Protocol Config Options (exemple tronqué)
class NASExtPCO(Packet):
    name = "Ext Protocol Configuration Options"
    fields_desc = [
        ByteField("eid", 0x7B),
        FieldLenField("length", 0x7, length_of="data", fmt=">H"),
        StrLenField("data", b'\x80\x00\n\x00\x00\r\x00', length_from=lambda pkt:pkt.length)
    ]

# Base NAS 5GS (session management)
class NAS5GSM(Packet):
    name = "NAS 5G Session Management"
    fields_desc = [
        ByteEnumField("epd", 0x2E, {0x2E: "5G Session Management"}),
        ByteField("psi", 1),  # PDU Session Identity
        ByteField("pti", 1),  # Procedure Transaction Identity
        ByteEnumField("msg_type", 0xc1, nas_msg_types),
        # PacketField("max_data_rate", NASMaxDataRate(), NASMaxDataRate),
        # PacketField("pdu_session", NASPDUSessionType(), NASPDUSessionType),
        # PacketField("scc_mode", NASSSCMode(), NASSSCMode),
        # PacketField("capabilities", NAS5GSMCapability(), NAS5GSMCapability),
        # PacketField("extended_config", NASExtPCO(), NASExtPCO)
    ]

bind_layers(NAS5GSM, NASMaxDataRate, msg_type=0xc1)
bind_layers(NASMaxDataRate, NASPDUSessionType)
bind_layers(NASPDUSessionType, NASSSCMode)
bind_layers(NASSSCMode, NAS5GSMCapability)
bind_layers(NAS5GSMCapability, NASExtPCO)