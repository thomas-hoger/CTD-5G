from scapy.all import send, sendp, sr1, Ether, IP, UDP, conf
from scapy.contrib.pfcp import *
import random, time
from src.pfcpToolkit.utils.logger import Log
from src.pfcpToolkit.utils.handleParams import HandleParams


class PFCPToolkit:
    """
    PFCPToolkit is a utility class to build, send, and manage PFCP messages for 5G core network testing.

    This class simplifies the creation and transmission of PFCP Association Setup,
    Session Establishment, Modification, and Deletion requests. It provides functionalities
    to randomize identifiers (SEID, TEID, Sequence numbers) and manage PFCP sessions programmatically.

    Main Features:
        - Build and send PFCP Association Setup Requests
        - Build and send PFCP Session Establishment Requests (with optional random FAR generation)
        - Build and send PFCP Session Modification Requests (targeting FARs)
        - Build and send PFCP Session Deletion Requests
        - Support for verbose logging, turbo sending mode, and Ethernet layer (sendp)

    Attributes:
        src_addr (str): Source IP address for PFCP messages.
        dest_addr (str): Destination IP address (UPF or peer).
        src_port (int): Source UDP port (default 8805).
        dest_port (int): Destination UDP port (default 8805).
        verbose (bool): Enables detailed logging output if True.
        classPrefix (str): Prefix used for internal logging tags.
        logger (Log): Logger instance for structured outputs.
        paramsHandler (HandleParams): Helper for parameter validation.
        seq (int): Sequence number for PFCP messages, auto-incremented.
        seid (int, optional): Default SEID for session management (can be overridden).
    """

    def __init__(
        self,
        src_addr=None,
        dest_addr=None,
        src_port=8805,
        dest_port=8805,
        verbose=False,
    ):
        conf.verb = 0  # Disable Scapy's verbose mode
        self.src_addr = src_addr
        self.dest_addr = dest_addr
        self.src_port = src_port
        self.dest_port = dest_port
        self.seq = 1
        self.verbose = verbose
        self.seid = None

        self.classPrefix = "[PFCP-TLKT]"
        self.logger = Log(self.classPrefix)

        self.paramsHandler = HandleParams(self.classPrefix)

        if verbose:
            self.logger.info("Verbose mode enabled")

    # Utility functions

    def new_seq(self, randomize=False):
        """
        Generate a new sequence number for PFCP messages.

        Args:
            randomize (bool, optional): Randomizes the sequence number. Defaults to False.

        Returns:
            integer: The generated sequence number.
        """

        if randomize:
            seqNbr = random.randint(1, 0xFFFFFFFF)
            return seqNbr
        seq = self.seq
        self.seq += 1
        if self.seq > 0xFFFFFFFF:
            self.seq = 1
        return seq

    # FAR Operations

    def Random_create_far(self):
        """
        Create a random FAR (Forwarding Action Rule) for PFCP messages.

        Returns:
            IE_CreateFAR: The created FAR packet.
        """
        return IE_CreateFAR(
            IE_list=[
                IE_FAR_Id(id=random.randint(1, 255)),
                IE_ApplyAction(FORW=1),
                IE_OuterHeaderCreation(
                    GTPUUDPIPV4=1,
                    TEID=random.randint(1, 0xFFFFFFFF),
                    ipv4=".".join(str(random.randint(1, 254)) for _ in range(4)),
                    port=2152,
                ),
            ]
        )

    def Update_FAR(self, far_id, apply_action_ie=IE_ApplyAction(FORW=1)):
        """
        Create a raw Update FAR (Forwarding Action Rule) Information Element for PFCP messages.

        Args:
            far_id (int): The FAR ID to update within the PFCP session.
            apply_action_ie (IE_ApplyAction, optional): The Apply Action IE specifying the new behavior. Defaults to IE_ApplyAction(FORW=1).

        Returns:
            Raw: Raw bytes representing the Update FAR IE, ready to be included in a PFCP message.
        """

        ie_update_far = IE_UpdateFAR(IE_list=[IE_FAR_Id(id=far_id), apply_action_ie])
        ie_update_far = Raw(bytes(ie_update_far))
        return ie_update_far

    # PFCP Message Building Functions

    def Build_PFCP_association_setup_req(
        self, src_addr=None, dest_addr=None, src_port=None, dest_port=None
    ):
        """
        Build a PFCP Association Setup Request packet.

        Args:
            src_addr (str, optional): Source IPv4 address of the PFCP initiator. Defaults to instance's src_addr.
            dest_addr (str, optional): Destination IPv4 address of the PFCP peer (e.g., UPF). Defaults to instance's dest_addr.
            src_port (int, optional): Source UDP port for the PFCP message. Defaults to instance's src_port.
            dest_port (int, optional): Destination UDP port for the PFCP message. Defaults to instance's dest_port.

        Returns:
            scapy.packet.Packet: The constructed PFCP Association Setup Request packet ready to send.
        """

        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port

        if not self.paramsHandler.check_parameters(
            {
                "src_addr": src_addr,
                "dest_addr": dest_addr,
                "src_port": src_port,
                "dest_port": dest_port,
            },
            "[Build_PFCP_association_setup_req]",
        ):
            return

        seq = self.new_seq()

        # Trick to bypass scapy's bad parsing
        node_id = Raw(bytes(IE_NodeId(id_type=0, ipv4=src_addr)))
        recovery_timestamp = Raw(
            bytes(IE_RecoveryTimeStamp(timestamp=int(time.time())))
        )
        pfcp_msg = (
            PFCP(version=1, message_type=5, seid=0, S=0, seq=seq)
            / node_id
            / recovery_timestamp
        )

        packet = (
            IP(src=src_addr, dst=dest_addr)
            / UDP(sport=src_port, dport=dest_port)
            / pfcp_msg
        )
        packet = packet.__class__(bytes(packet))
        return packet

    def Build_PFCP_session_establishment_req(
        self,
        src_addr=None,
        dest_addr=None,
        src_port=None,
        dest_port=None,
        seid=0x1,
        ue_addr=None,
        teid=0x11111111,
        precedence=255,
        interface=1,
        random_seq=False,
        random_far_number=0,
    ):
        """
        Build a PFCP Session Establishment Request packet.

        Args:
            src_addr (str, optional): Source IPv4 address of the PFCP message sender. Defaults to instance's src_addr.
            dest_addr (str, optional): Destination IPv4 address (usually the UPF). Defaults to instance's dest_addr.
            src_port (int, optional): UDP source port for sending the PFCP message. Defaults to instance's src_port.
            dest_port (int, optional): UDP destination port for receiving the PFCP message. Defaults to instance's dest_port.
            seid (int, optional): Session Endpoint Identifier to assign to the session. Defaults to 0x1.
            ue_addr (str, optional): IPv4 address of the User Equipment (UE) to be associated with the PDR. Defaults to None.
            teid (int, optional): Tunnel Endpoint Identifier for GTP-U encapsulation. Defaults to 0x11111111.
            precedence (int, optional): Priority value assigned to the PDR (lower values have higher priority). Defaults to 255.
            interface (int, optional): Source interface type for the packet detection (e.g., 1 = Access). Defaults to 1.
            random_seq (bool, optional): If True, randomizes the PFCP sequence number. Defaults to False.
            random_far_number (int, optional): Number of additional randomly generated FARs to append. Defaults to 0.

        Returns:
            scapy.packet.Packet: The constructed PFCP Session Establishment Request packet ready for transmission.
        """

        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port
        seid = seid or self.seid

        if not self.paramsHandler.check_parameters(
            {
                "src_addr": src_addr,
                "dest_addr": dest_addr,
                "src_port": src_port,
                "dest_port": dest_port,
                "seid": seid,
            },
            "[Build_PFCP_session_establishment_req]",
        ):
            return

        seq = self.new_seq(randomize=random_seq)

        ie_nodeid = Raw(bytes(IE_NodeId(id_type=0, ipv4=src_addr)))
        ie_fseid = Raw(bytes(IE_FSEID(seid=seid, v4=1, ipv4=src_addr)))

        ie_createpdr = Raw(
            bytes(
                IE_CreatePDR(
                    IE_list=[
                        IE_PDR_Id(id=1),
                        IE_Precedence(precedence=precedence),
                        IE_PDI(
                            IE_list=[
                                IE_SourceInterface(interface=interface),
                                IE_FTEID(TEID=teid, V4=1, ipv4=ue_addr),
                            ]
                        ),
                        IE_FAR_Id(id=1),
                    ]
                )
            )
        )

        ie_createfar = Raw(
            bytes(
                IE_CreateFAR(
                    IE_list=[
                        IE_FAR_Id(id=1),
                        IE_ApplyAction(FORW=1),
                        IE_OuterHeaderCreation(
                            GTPUUDPIPV4=1, TEID=teid, ipv4=ue_addr, port=2152
                        ),
                    ]
                )
            )
        )

        pfcp_msg = (
            PFCP(version=1, message_type=50, seid=0, S=1, seq=seq)
            / ie_nodeid
            / ie_fseid
            / ie_createpdr
            / ie_createfar
        )

        if random_far_number:
            for i in range(random_far_number):
                pfcp_msg = pfcp_msg / Raw(bytes(self.Random_create_far()))

        pkt = (
            IP(src=src_addr, dst=dest_addr)
            / UDP(sport=src_port, dport=dest_port)
            / pfcp_msg
        )
        pkt = pkt.__class__(bytes(pkt))  # Recalcul final
        return pkt

    def Build_PFCP_session_deletion_req(
        self,
        seid=None,
        src_addr=None,
        dest_addr=None,
        src_port=None,
        dest_port=None,
        random_seq=False,
    ):
        """
        Build a PFCP Session Establishment Request packet.

        Args:
            src_addr (str, optional): Source IP address for the PFCP message. Defaults to instance's src_addr.
            dest_addr (str, optional): Destination IP address (typically the UPF). Defaults to instance's dest_addr.
            src_port (int, optional): Source UDP port for the PFCP message. Defaults to instance's src_port.
            dest_port (int, optional): Destination UDP port for the PFCP message. Defaults to instance's dest_port.
            seid (int, optional): Session Endpoint Identifier (SEID) for the session. Defaults to 0x1.
            ue_addr (str, optional): User Equipment IP address (UE IP). Defaults to None.
            teid (int, optional): Tunnel Endpoint Identifier for GTP-U encapsulation. Defaults to 0x11111111.
            precedence (int, optional): Priority level for the PDR. Defaults to 255.
            interface (int, optional): Source interface type (1 = Access). Defaults to 1.
            random_seq (bool, optional): Randomize the PFCP message sequence number if True. Defaults to False.
            random_far_number (int, optional): Number of additional FARs to randomly create and append. Defaults to 0.

        Returns:
            scapy.packet.Packet: The constructed PFCP Session Establishment Request packet ready to send.
        """

        seid = seid or self.seid
        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port

        if not self.paramsHandler.check_parameters(
            {
                "src_addr": src_addr,
                "dest_addr": dest_addr,
                "src_port": src_port,
                "dest_port": dest_port,
                "seid": seid,
            },
            "[Build_PFCP_session_deletion_req]",
        ):
            return

        node_id = Raw(bytes(IE_NodeId(id_type=0, ipv4=src_addr)))

        pfcp_msg = (
            PFCP(
                version=1,
                message_type=54,
                seid=seid,
                S=1,
                seq=self.new_seq(randomize=random_seq),
            )
            / node_id
        )
        packet = (
            IP(src=src_addr, dst=dest_addr)
            / UDP(sport=src_port, dport=dest_port)
            / pfcp_msg
        )
        packet = packet.__class__(bytes(packet))
        return packet

    def Build_PFCP_session_modification_req(
        self,
        seid,
        far_id,
        tdest_addr=None,
        src_addr=None,
        dest_addr=None,
        src_port=None,
        dest_port=None,
        apply_action=["FORW"],
        teid=0x11111111,
    ):
        """
        Build a PFCP Session Modification Request packet.

        Args:
            seid (int): Session Endpoint Identifier (SEID) of the session to modify.
            far_id (int): Forwarding Action Rule (FAR) ID to update.
            src_addr (str, optional): Source IPv4 address for the PFCP message. Defaults to instance's src_addr.
            dest_addr (str, optional): Destination IPv4 address (typically the UPF). Defaults to instance's dest_addr.
            src_port (int, optional): UDP source port for sending the PFCP message. Defaults to instance's src_port.
            dest_port (int, optional): UDP destination port for the PFCP message. Defaults to instance's dest_port.
            apply_action (list or str, optional): Actions to apply to the FAR (e.g., ["FORW", "DUPL"]). Defaults to ["FORW"].

        Returns:
            scapy.packet.Packet: The constructed PFCP Session Modification Request packet ready for transmission.
        """
        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port
        seid = seid or self.seid

        if not self.paramsHandler.check_parameters(
            {
                "src_addr": src_addr,
                "dest_addr": dest_addr,
                "src_port": src_port,
                "dest_port": dest_port,
                "seid": seid,
                "far_id": far_id,
            },
            "[Build_PFCP_session_modification_req]",
        ):
            return

        # Si une seule action est passée sous forme de string, on la convertit en liste
        if isinstance(apply_action, str):
            apply_action = [apply_action]

        # On prépare dynamiquement le dictionnaire des flags
        action_flags = {"FORW": 0, "DROP": 0, "BUFF": 0, "NOCP": 0, "DUPL": 0}

        for action in apply_action:
            action = action.upper()
            if action in action_flags:
                action_flags[action] = 1
            else:
                self.logger.error(f"Unknown apply action: {action}")

        apply_action_ie = IE_ApplyAction(**action_flags)

        ie_update_far = None

        if action_flags["DUPL"] == 1:
            ie_update_far = IE_UpdateFAR(
                IE_list=[
                    IE_FAR_Id(id=far_id),
                    apply_action_ie,
                    IE_UpdateDuplicatingParameters(
                        IE_list=[
                            IE_OuterHeaderCreation(
                                GTPUUDPIPV4=1, TEID=teid, ipv4=tdest_addr, port=2152
                            ),
                        ]
                    ),
                ],
            )
        elif (
            action_flags["FORW"] == 1
            and action_flags["DUPL"] == 0
            and tdest_addr is not None
        ):
            ie_update_far = IE_UpdateFAR(
                IE_list=[
                    IE_FAR_Id(id=far_id),
                    apply_action_ie,
                    IE_OuterHeaderCreation(
                        GTPUUDPIPV4=1, TEID=teid, ipv4=tdest_addr, port=2152
                    ),
                ]
            )
        elif (
            action_flags["FORW"] == 1
            and action_flags["DUPL"] == 0
            or action_flags["DROP"] == 1
        ):
            ie_update_far = IE_UpdateFAR(
                IE_list=[
                    IE_FAR_Id(id=far_id),
                    apply_action_ie,
                ]
            )

        ie_update_far = Raw(bytes(ie_update_far))
        update_ie = ie_update_far

        packet = (
            PFCP(version=1, message_type=52, S=1, seid=seid, seq=self.new_seq(True))
            / update_ie
        )

        packet = (
            IP(src=src_addr, dst=dest_addr)
            / UDP(sport=src_port, dport=dest_port)
            / packet
        )
        packet = packet.__class__(bytes(packet))
        return packet

    def Send_PFCP_association_setup_req(
        self, src_addr=None, dest_addr=None, src_port=None, dest_port=None
    ):
        """
        Send a PFCP Association Setup Request to a PFCP peer (typically a UPF).

        Args:
            src_addr (str, optional): Source IPv4 address for the PFCP message. Defaults to instance's src_addr.
            dest_addr (str, optional): Destination IPv4 address (UPF). Defaults to instance's dest_addr.
            src_port (int, optional): UDP source port. Defaults to instance's src_port.
            dest_port (int, optional): UDP destination port. Defaults to instance's dest_port.

        Returns:
            None
        """

        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port

        if not self.paramsHandler.check_parameters(
            {
                "src_addr": src_addr,
                "dest_addr": dest_addr,
                "src_port": src_port,
                "dest_port": dest_port,
            },
            "[Send_PFCP_association_setup_req]",
        ):
            return

        seq = self.new_seq()

        pfcp_association_setup_req = self.Build_PFCP_association_setup_req(
            src_addr=src_addr,
            dest_addr=dest_addr,
            src_port=src_port,
            dest_port=dest_port,
        )
        send(pfcp_association_setup_req)
        if self.verbose:
            self.logger.success(f"PFCP Association Setup packet sent to {dest_addr}")

    def Send_PFCP_session_establishment_req(
        self,
        src_addr=None,
        dest_addr=None,
        src_port=None,
        dest_port=None,
        seid=0x1,
        ue_addr=None,
        teid=0x11111111,
        precedence=255,
        interface=1,
        random_seq=False,
        random_far_number=0,
        use_sendp=False,
    ):
        """
        Send a PFCP Session Establishment Request to a PFCP peer.

        Args:
            src_addr (str, optional): Source IPv4 address for the PFCP message. Defaults to instance's src_addr.
            dest_addr (str, optional): Destination IPv4 address (UPF). Defaults to instance's dest_addr.
            src_port (int, optional): UDP source port. Defaults to instance's src_port.
            dest_port (int, optional): UDP destination port. Defaults to instance's dest_port.
            seid (int, optional): Session Endpoint Identifier (SEID) for the session. Defaults to 0x1.
            ue_addr (str, optional): IPv4 address of the User Equipment (UE). Defaults to None.
            teid (int, optional): Tunnel Endpoint Identifier for GTP-U encapsulation. Defaults to 0x11111111.
            precedence (int, optional): Priority value for the PDR. Defaults to 255.
            interface (int, optional): Source interface type for the PDR (e.g., 1 = Access). Defaults to 1.
            random_seq (bool, optional): If True, randomizes the PFCP sequence number. Defaults to False.
            random_far_number (int, optional): Number of additional random FARs to include. Defaults to 0.
            use_sendp (bool, optional): If True, sends using Layer 2 (sendp with Ethernet). Defaults to False.

        Returns:
            None
        """

        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port
        seid = seid or self.seid
        seq = self.new_seq(randomize=random_seq)

        if not self.paramsHandler.check_parameters(
            {
                "src_addr": src_addr,
                "dest_addr": dest_addr,
                "src_port": src_port,
                "dest_port": dest_port,
                "seid": seid,
                "ue_addr": ue_addr,
            },
            "[Send_PFCP_session_establishment_req]",
        ):
            return

        if self.verbose:
            self.logger.info(
                f"Sending PFCP session establishment request to {dest_addr} with SEID {seid}, UE address {ue_addr}, TEID {teid}, precedence {precedence}, interface {interface}"
            )

        pfcp_session_establishment_req = self.Build_PFCP_session_establishment_req(
            src_addr=src_addr,
            dest_addr=dest_addr,
            src_port=src_port,
            dest_port=dest_port,
            seid=seid,
            ue_addr=ue_addr,
            teid=teid,
            precedence=precedence,
            interface=interface,
            random_seq=random_seq,
            random_far_number=random_far_number,
        )
        if use_sendp:
            sendp(Ether() / pfcp_session_establishment_req, iface="eth0")
        else:
            send(pfcp_session_establishment_req)
        if self.verbose:
            self.logger.success(
                f"PFCP Session Establishment packet sent to {dest_addr} with SEID {seid}"
            )

    def Send_PFCP_session_deletion_req(
        self,
        seid,
        src_addr=None,
        dest_addr=None,
        src_port=None,
        dest_port=None,
        turbo=False,
        random_seq=False,
    ):
        """
        Send a PFCP Session Deletion Request to a PFCP peer (typically a UPF).

        Args:
            seid (int): Session Endpoint Identifier (SEID) of the session to delete.
            src_addr (str, optional): Source IPv4 address for the PFCP message. Defaults to instance's src_addr.
            dest_addr (str, optional): Destination IPv4 address (typically the UPF). Defaults to instance's dest_addr.
            src_port (int, optional): UDP source port for sending the PFCP message. Defaults to instance's src_port.
            dest_port (int, optional): UDP destination port for the PFCP message. Defaults to instance's dest_port.
            turbo (bool, optional): If True, send the packet without waiting for a response (fire-and-forget mode). Defaults to False.
            random_seq (bool, optional): If True, randomize the sequence number in the PFCP message. Defaults to False.

        Returns:
            int or None: PFCP Cause IE value received in response if available, otherwise None.
        """

        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port

        if not self.paramsHandler.check_parameters(
            {
                "src_addr": src_addr,
                "dest_addr": dest_addr,
                "src_port": src_port,
                "dest_port": dest_port,
                "seid": seid,
            },
            "[Send_PFCP_session_deletion_req]",
        ):
            return

        seq = self.new_seq()

        req = self.Build_PFCP_session_deletion_req(
            seid=seid,
            src_addr=src_addr,
            dest_addr=dest_addr,
            src_port=src_port,
            dest_port=dest_port,
            random_seq=random_seq,
        )
        if turbo:
            send(req)
            return

        res = sr1(req)
        if not res:
            self.logger.error("No response received for PFCP session deletion request")

        pfcp_cause = None

        for ie in res[PFCP].IE_list:
            if isinstance(ie, IE_Cause):
                pfcp_cause = ie.cause
                break
        if self.verbose:
            self.logger.info(
                f"PFCP Session Deletion response received with cause: {pfcp_cause}"
            )

        return pfcp_cause

    def Send_PFCP_session_modification_req(
        self,
        seid,
        far_id,
        tdest_addr,
        src_addr=None,
        dest_addr=None,
        src_port=None,
        dest_port=None,
        apply_action=["FORW"],
    ):
        """
        Send a PFCP Session Modification Request to a PFCP peer (typically a UPF).

        Args:
            seid (int): Session Endpoint Identifier (SEID) of the session to modify.
            far_id (int): Forwarding Action Rule (FAR) ID to update.
            src_addr (str, optional): Source IPv4 address for the PFCP message. Defaults to instance's src_addr.
            dest_addr (str, optional): Destination IPv4 address (typically the UPF). Defaults to instance's dest_addr.
            src_port (int, optional): UDP source port for sending the PFCP message. Defaults to instance's src_port.
            dest_port (int, optional): UDP destination port for the PFCP message. Defaults to instance's dest_port.
            apply_action (list or str, optional): Actions to apply to the FAR (e.g., ["FORW", "DUPL"]). Defaults to ["FORW"].

        Returns:
            None
        """

        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port

        if not self.paramsHandler.check_parameters(
            {
                "src_addr": src_addr,
                "dest_addr": dest_addr,
                "src_port": src_port,
                "dest_port": dest_port,
                "seid": seid,
                "far_id": far_id,
            },
            "[Send_PFCP_session_modification_req]",
        ):
            return

        pfcp_session_modification_req = self.Build_PFCP_session_modification_req(
            seid=seid,
            far_id=far_id,
            tdest_addr=tdest_addr,
            src_addr=src_addr,
            dest_addr=dest_addr,
            src_port=src_port,
            dest_port=dest_port,
            apply_action=apply_action,
        )

        send(pfcp_session_modification_req)

        if self.verbose:
            self.logger.success(
                f"PFCP Session Modification packet sent to {dest_addr} with SEID {seid} and FAR ID {far_id}"
            )
