from src.pfcpToolkit.pfcp_toolkit import PFCPToolkit
import random, time, threading, ipaddress
from scapy.all import send, sr1, conf

from scapy.contrib.pfcp import *

from src.pfcpToolkit.utils.logger import Log
from src.pfcpToolkit.utils.handleParams import HandleParams

from collections import defaultdict


class PFCPFuzzer:
    def __init__(self):

        self.verbose = False
        conf.verb = 0

    def set_verbose(self, verbose):
        """
        Set the verbosity level for logging.
        """
        self.verbose = verbose

    def start_PFCP_SEID_fuzzing(
        self,
        upf_addr,
        src_addr,
        max_seid=10000,
        max_far_discover=100,
        src_port=8805,
        dest_port=8805,
    ):
        """
        Start PFCP SEID fuzzing
        """

        # Create a PFCPToolkit object
        PFCPToolkit_obj = PFCPToolkit(
            src_addr=src_addr,
            dest_addr=upf_addr,
            src_port=src_port,
            dest_port=dest_port,
        )

        valid_seid_list = list()
        far_id = 1

        print(f"Starting PFCP SEID fuzzing on {upf_addr} with max SEID {max_seid}")
        for seid in range(1, max_seid):

            packet = PFCPToolkit_obj.Build_PFCP_session_modification_req(
                seid=seid, far_id=far_id
            )

            res = sr1(packet)

            pfcp_cause = None
            for ie in res[PFCP].IE_list:
                if isinstance(ie, IE_Cause):
                    pfcp_cause = ie.cause
                    break

            if pfcp_cause == 1:
                print(f"Discovered SEID: {hex(seid)}")
                valid_seid_list.append(seid)
            elif pfcp_cause == 65:
                # in case the far_id is not incremented from 1
                if far_id >= max_far_discover:
                    far_id = 0

                far_id += 1

        if self.verbose:
            print(f"Fuzzing completed, {len(valid_seid_list)} SEIDs discovered")
        return valid_seid_list

    def start_PFCP_FARID_fuzzing(
        self,
        upf_addr,
        src_addr,
        max_seid=100,
        max_far_discover=100,
        src_port=8805,
        dest_port=8805,
        seid=None,
    ):
        """
        Start PFCP FAR
        """

        # Create a PFCPToolkit object
        PFCPToolkit_obj = PFCPToolkit(
            src_addr=src_addr,
            dest_addr=upf_addr,
            src_port=src_port,
            dest_port=dest_port,
        )

        valid_farid_per_seid = defaultdict(list)

        if seid is not None:
            for farid in range(1, max_far_discover):

                packet = PFCPToolkit_obj.Build_PFCP_session_modification_req(
                    seid=seid, far_id=farid
                )

                res = sr1(packet)

                pfcp_cause = None
                for ie in res[PFCP].IE_list:
                    if isinstance(ie, IE_Cause):
                        pfcp_cause = ie.cause
                        break

                if pfcp_cause == 1:
                    print(f"Discovered FAR-ID: {hex(farid)}")
                    valid_farid_per_seid[seid].append(farid)

            total = sum(len(fars) for fars in valid_farid_per_seid.values())
            print(f"Fuzzing completed, {total} FAR-IDs discovered")
            return dict(valid_farid_per_seid)

        print(f"No SEID provided, fuzzing SEIDs")
        print(
            f"Starting PFCP FAR-ID fuzzing on {upf_addr} with max FAR-ID {max_far_discover}"
        )

        for seid1 in range(1, max_seid):

            for farid in range(1, max_far_discover):

                packet = PFCPToolkit_obj.Build_PFCP_session_modification_req(
                    seid=seid1, far_id=farid
                )

                res = sr1(packet)

                pfcp_cause = None
                for ie in res[PFCP].IE_list:
                    if isinstance(ie, IE_Cause):
                        pfcp_cause = ie.cause
                        break

                if pfcp_cause == 1:
                    print(f"Discovered FAR-ID: {hex(farid)}")
                    valid_farid_per_seid[seid1].append(farid)

        if self.verbose:
            total = sum(len(fars) for fars in valid_farid_per_seid.values())

            print(f"Fuzzing completed, {total} FAR-IDs discovered")
        return dict(valid_farid_per_seid)
