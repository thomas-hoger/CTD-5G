from __future__ import annotations

from enum import Enum
import re

from src.utils.common import ueransim_exec, ue_list, get_docker_iface_from_ip

class PDUState(Enum):
    ACTIVE = "PS-ACTIVE"
    INACTIVE = "PS-INACTIVE"

class PDUSession:
    def __init__(self, session_id: int, imsi:str, address: str, iface: str, state: str = PDUState.ACTIVE):
        self.id = session_id
        self.imsi = imsi
        self.state = state
        self.address = address
        self.iface = iface

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
            list[dict]: A list of dictionaries, each containing session_id, state, address, and iface.
        """
        
        ps_result = ueransim_exec(f"./nr-cli {imsi} -e ps-list") 
        matches   = re.findall(r'PDU Session(\d+):\s+state:\s+(\S+).*?address:\s+(\d+\.\d+\.\d+\.\d+)', ps_result, re.DOTALL)
        sessions  = []
        for session_id, state, address in matches:
            sessions.append({
                "session_id": int(session_id),
                "imsi": imsi,
                "state": PDUState(state),
                "address": address,
                "iface": get_docker_iface_from_ip("ueransim",address) 
            })
        return sessions

    def restart(session: PDUSession) -> bool:
        output = ueransim_exec(f"./nr-cli {session.imsi} -e 'ps-release {session.id}'")
        return "triggered" in output 
        
        # Check if the session is temporarily inactive
        # updated_sessions = session.get_ue_sessions()
        # for updated_session in updated_sessions:
        #     if updated_session["session_id"] == session.id and updated_session["state"] != PDUState.ACTIVE.value:
        #         return True
            
        # return False

