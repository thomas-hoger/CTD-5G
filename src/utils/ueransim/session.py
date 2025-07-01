from __future__ import annotations

from enum import Enum
import re
import json
import random

from src.utils.common import docker_exec, ueransim_exec, ue_list, get_docker_iface_from_ip

class PDUState(Enum):
    ACTIVE = "PS-ACTIVE"
    INACTIVE = "PS-INACTIVE"

class PDUSession:
    
    def __init__(self, ps_id:int, imsi:str, address: str, iface: str, state: str = PDUState.ACTIVE):
        self.ps_id = ps_id
        self.imsi = imsi
        self.state = state
        self.address = address
        self.iface = iface
        
        self.seid = PDUSession.get_seid_by_ip(self.address)
        self.teid = PDUSession.get_teid_by_ip(self.address)
        
    def get_random_ip():
        session_infos = docker_exec("upf", "./gtp5g-tunnel list pdr")
        session_infos = json.loads(session_infos)
        session = random.choice(session_infos)
        return session["PDI"]["UEAddr"]
            
    def get_seid_by_ip(ip:str) -> int | None:
        session_infos = docker_exec("upf", "./gtp5g-tunnel list pdr")
        session_infos = json.loads(session_infos)
        
        for info in session_infos:

            if info["PDI"]["UEAddr"] == ip:
                return int(info["SEID"])
        
    def get_teid_by_ip(ip:str) -> int | None:
        session_infos = docker_exec("upf", "./gtp5g-tunnel list pdr")
        session_infos = json.loads(session_infos)
        
        for info in session_infos:

            if info["PDI"]["UEAddr"] == ip:
                fteid = info["PDI"]["FTEID"]
                
                if fteid and "TEID" in fteid : 
                    return int(fteid["TEID"])

    def get_far_id_by_seid(seid:int) -> list[int] :
    
        far_infos = docker_exec("upf", "./gtp5g-tunnel list far")
        far_infos = json.loads(far_infos)

        far_ids = []
        for info in far_infos:
            
            if int(info["SEID"]) == seid:
                far_ids.append(info["ID"])
                
        return far_ids
                
    def get_sessions() -> list[PDUSession]:
        sessions = []
        for ue in ue_list:
            for session in ue.sessions:
                sessions.append(session)
        return sessions 

    def get_active_sessions() -> list[PDUSession]:
        sessions = PDUSession.get_sessions()
        return [session for session in sessions if session.state == PDUState.ACTIVE]

    def get_inactive_sessions() -> list[PDUSession]:
        sessions = PDUSession.get_sessions()
        return [session for session in sessions if session.state == PDUState.INACTIVE]

    def get_ue_sessions(imsi:str) -> list[dict]:
        """
        Retrieve a list of PDU session details for a given IMSI.
        Args:
            imsi (str): The IMSI of the UE to query.
        Returns:
            list[dict]: A list of dictionaries, each containing state, address, and iface.
        """
        
        ps_result = ueransim_exec(f"./nr-cli {imsi} -e ps-list") 
        matches   = re.findall(r'PDU Session(\d+):\s+state:\s+(\S+).*?address:\s+(\d+\.\d+\.\d+\.\d+)', ps_result, re.DOTALL)
        sessions  = []
                
        for ps_id, state, address in matches:
            sessions.append({
                "ps_id" : ps_id,
                "imsi": imsi,
                "state": PDUState(state),
                "address": address,
                "iface": get_docker_iface_from_ip("ueransim",address) 
            })
        return sessions

    def restart(session: PDUSession) -> bool:
        output = ueransim_exec(f"./nr-cli {session.imsi} -e 'ps-release {session.ps_id}'")
        return "triggered" in output 
        
        # Check if the session is temporarily inactive
        # updated_sessions = session.get_ue_sessions()
        # for updated_session in updated_sessions:
        #     if updated_session["session_id"] == session.id and updated_session["state"] != PDUState.ACTIVE.value:
        #         return True
            
        # return False

    def uplink_traffic(session: PDUSession, packet_quantity:int=10, dn_domain:str="google.com") -> bool:

        command = f"ping {dn_domain} -I {session.iface} -c {packet_quantity}"
        res     = ueransim_exec(command)
        match   = re.search(r"(\d+)\s+packets transmitted,\s+(\d+)\s+received", res)
        if match:
            # transmitted = int(match.group(1))
            received = int(match.group(2))
            return received > 0
        return False

    def downlink_traffic(session: PDUSession, packet_quantity:int=3) -> bool:
        
        command = f"ping {session.address} -I upfgtp -c {packet_quantity}"
        res     = docker_exec("upf", command)
        match   = re.search(r"(\d+)\s+packets transmitted,\s+(\d+)\s+received", res)
        if match:
            # transmitted = int(match.group(1))
            received = int(match.group(2))
            return received > 0
        return False
