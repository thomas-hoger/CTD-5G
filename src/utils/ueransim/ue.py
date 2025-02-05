from __future__ import annotations

import re
import random
import time
import os 

from enum import Enum

from src.utils.common import ueransim_exec, ue_list, UE_CONFIG_PATH, ueransim_timeout
from src.utils.ueransim.gnb import gNodeB
from src.utils.ueransim.session import PDUSession,PDUState
from src.utils.ueransim.database import known_imsis

class UEState(Enum):
    CONNECTED = "CM-CONNECTED"
    IDLE = "CM-IDLE"    
        
class UserEquipment:
    ue_id_counter = 1  # class variable

    def __init__(self, id:int, ran_id: int, amf_id:int, imsi: str, sessions:list[PDUSession], state=UEState.CONNECTED):
        self.id = id
        self.ran_id = ran_id
        self.amf_id = amf_id
        self.imsi = imsi
        self.state = state
        self.sessions = sessions

        UserEquipment.ue_id_counter += 1
        
    def get_session_by_id(self, session_id: int) -> PDUSession | None:
        for session in self.sessions:
            if session.id == session_id:
                return session

    def get_ue_by_imsi(imsi: str) -> UserEquipment | None:
        """
        Returns the UserEquipment instance with the specified IMSI.
        Args:
            imsi (str): The IMSI of the User Equipment to find.
        Returns:
            UserEquipment | None: The UserEquipment instance if found, otherwise None.
        """
        for ue in ue_list:
            if ue.imsi == imsi:
                return ue
        return None

    # ------- UE registration

    def get_registered() -> list[str]:
        "Returns a list of IMSIs that are currently registered in the UERANSIM network."
        components = ueransim_exec("./nr-cli --dump")
        imsi_names = re.findall(r"^imsi-.*",components, re.MULTILINE)
        return imsi_names

    def get_available_imsi() -> list[str]:
        "Returns a random IMSI that is not currently registered."
        available_imsi = list(set(known_imsis) - set(UserEquipment.get_registered()))
        if len(available_imsi) > 0:
            return random.choice(available_imsi)
        else : 
            return []

    def register_new(imsi:str) -> UserEquipment | None:
        """
        Attempts to register a User Equipment (UE) with the given IMSI on the network.
        Args:
            imsi (str): The IMSI of the UE to register.
        Returns:
            UserEquipment | None: The registered UserEquipment instance if successful, otherwise None.
        """
        
        gnb = gNodeB.get_registered_gnb()[0]  # Get the first registered gNB
        ues_in_gnb = gNodeB.get_registered_ues_in_gnb(gnb) # Get the previous list of UEs in the gNB
        
        ueransim_exec(f"./nr-ue -c {UE_CONFIG_PATH} -i {imsi}", read=False) # Start the UE with the given IMSI
            
        is_registered = UserEquipment.wait_ue_registration(imsi, ues_in_gnb)
        have_session = PDUSession.wait_ue_session_created(imsi)
            
        # Wait for the ue to be registered
        if is_registered and have_session:
                
            new_ues_in_gnb = [ue_dict for ue_dict in gNodeB.get_registered_ues_in_gnb(gnb) if ue_dict not in ues_in_gnb]
            new_ue_in_gnb  = new_ues_in_gnb[0]  # Get the first new UE
                        
            sessions = [
                PDUSession(
                    ps_id    = session["ps_id"],
                    imsi     = imsi,
                    address  = session["address"],
                    iface    = session["iface"],
                    state    = session["state"]
                )
                for session in PDUSession.get_ue_sessions(imsi)
            ]
            
            # The second session don't seem to work 
            # So we only keep the first one
            sessions = sessions[:1]

            ue = UserEquipment(
                id = int(new_ue_in_gnb["ue-id"]),
                ran_id = int(new_ue_in_gnb["ran-ngap-id"]),
                amf_id = int(new_ue_in_gnb["amf-ngap-id"]),
                imsi = imsi,
                sessions = sessions,
                state = UEState.CONNECTED
            )
            
            global ue_list
            ue_list.append(ue)  # Add the new UE to the global list
            return ue
            
        else : # UE was not registered properly in UERANSIM
            # Also kill the process to avoid zombie processes
            ueransim_exec(f"pkill -f {imsi}")
            return None

    def wait_ue_registration(imsi:str, ues_in_gnb:list[dict]) -> bool:
        """
        Waits for a UE (User Equipment) with the specified IMSI to register.
        Args:
            imsi (str): The IMSI of the UE to wait for registration.
        Returns:
            bool: True if the UE is registered and has a session within the timeout period, False otherwise.
        """
        
        gnb = gNodeB.get_registered_gnb()[0]  # Get the first registered gNB
        
        # Wait until success or timeout
        for _ in range(ueransim_timeout):
            
            # Do the difference to find the new UE in the gNB
            # This is necessary because the gNB keep its own ue_id and they are needed to manage sessions
            new_ues_in_gnb = [ue_dict for ue_dict in gNodeB.get_registered_ues_in_gnb(gnb) if ue_dict not in ues_in_gnb]
            
            # Wait for a new UE appear in the ueransim cli and its session to be registered
            if len(new_ues_in_gnb) > 0:
                return True
            
            time.sleep(1)
                
        return False
    
    def wait_ue_deregistration(ue: UserEquipment) -> bool:
        """
        Waits for the specified UE to deregister by polling the list of registered UEs until the UE's IMSI is absent or a timeout occurs.
        Args:
            ue (UserEquipment): The user equipment instance to check for deregistration.
        Returns:
            bool: True if the UE is deregistered before timeout, False otherwise.
        """
        # Wait until success or timeout
        for _ in range(ueransim_timeout):
            registered_ues = UserEquipment.get_registered()
            if ue.imsi not in registered_ues : 
                return True
            
            time.sleep(1)
        return False
    
    def deregister(ue: UserEquipment) -> bool:
        """
        Deregisters a User Equipment (UE) by IMSI, kills its process to prevent reboot, and returns True if deregistration was successful.
        Args:
            ue (UserEquipment): The user equipment instance to deregister.
        Returns:
            bool: True if the UE was successfully deregistered, False otherwise.
        """

        imsi = ue.imsi
        
        # Send deregistration messages
        ueransim_exec(f"./nr-cli {imsi} -e 'deregister normal'")
                
        # Also kill the process to avoid automatic reboot
        ueransim_exec(f"pkill -f {imsi}")
            
        is_deregistered = ue.wait_ue_deregistration()
        if is_deregistered:
            global ue_list
            ue_list.remove(ue)  # Remove the UE from the global list
            return True
        
        else : 
            return False

    def terminate_all() -> None:
        global ue_list
        ue_list.clear()
        ueransim_exec("pkill -f imsi")
        time.sleep(1)

    # ------- UE state management

    def get_status(ue: UserEquipment) -> UEState:
        """
        Returns the connection management (cm) state of the given UserEquipment by executing a status command and parsing its output.
        Args:
            ue (UserEquipment): The user equipment instance to query.
        Returns:
            UEState: The cm-state of the user equipment if found, otherwise None.
        """

        status = ueransim_exec(f"./nr-cli {ue.imsi} -e status") # get the status of the ue
        match  = re.search(r"cm-state:\s*(\S+)", status) # sarch in the command output for the cm-state
        if match: 
            return UEState(match.group(1))

    def get_idle_ues() -> list[UserEquipment]:
        return [ue for ue in ue_list if ue.state == UEState.IDLE]   
        
    def get_connected_ues() -> list[UserEquipment]:
        return [ue for ue in ue_list if ue.state == UEState.CONNECTED]   

    def wait_state_change(ue: UserEquipment) -> bool:
        """
        Waits for the UserEquipment (UE) to reach the desired state within a timeout period.
        Update the new state to ue.state if there are changes
        Args:
            ue (UserEquipment): The user equipment instance to monitor.
        Returns:
            bool: True if the UE reaches the desired state within the timeout, False otherwise.
        """
        
        for _ in range(ueransim_timeout):
            new_status = ue.get_status()
            if new_status != ue.state: # check if the ue is in IDLE state
                ue.state = new_status
                return True
            
            time.sleep(1)
        return False

    def context_release(ue: UserEquipment) -> bool:
        """
        Sets the given UserEquipment (UE) to IDLE state if currently CONNECTED.
        Args:
            ue (UserEquipment): The user equipment instance to set to IDLE.
        Returns:
            bool: True if the UE was successfully set to IDLE, False otherwise.
        """
        
        gnb = gNodeB.get_registered_gnb()[0]
        
        if ue.state == UEState.CONNECTED:
            ueransim_exec(f"./nr-cli {gnb} -e 'ue-release {ue.id}'") # release the ue
            state_changed = ue.wait_state_change()
            if state_changed and ue.state == UEState.IDLE: 
                return True
        
        return False

    def get_active_sessions(ue: UserEquipment) -> list[PDUSession]:
                
        active_sessions = []
        for session in ue.sessions:
            if session.state == PDUState.ACTIVE:
                active_sessions.append(session)
                
        return active_sessions 
    
    def uplink_wake(ue: UserEquipment) -> bool:
        """
        Attempts to wake up a User Equipment (UE) from IDLE state by sending uplink traffic to a specified domain.
        If the UE transitions to CM-CONNECTED state, updates its state to CONNECTED.
        Args:
            ue (UserEquipment): The user equipment instance to wake up.
            packet_quantity (int): Number of packets to send.
            dn_domain (str): Destination domain for the ping command.
        Returns:
            bool: True if the UE was successfully woken up and registered, False otherwise.
        """
        
        if ue.state == UEState.IDLE:
            
            active_sessions = ue.get_active_sessions() 
            if len(active_sessions) < 1:
                return False
            session = random.choice(active_sessions)
            
            sent = session.uplink_traffic()  # Send ICMP packets to wake up the UE
            if sent:
            
                # Check if the UE is now connected
                state_changed = ue.wait_state_change()
                if state_changed and ue.state == UEState.CONNECTED: 
                    return True
        
        return False

    def downlink_wake(ue: UserEquipment) -> bool:
        """
        Attempts to wake up a user equipment (UE) from IDLE state by sending downlink packets.
        Returns True if the UE transitions to CONNECTED state, otherwise False.
        Args:
            ue (UserEquipment): The user equipment instance to wake.
        Returns:
            bool: True if UE is successfully woken up, False otherwise.
        """
        
        if ue.state == UEState.IDLE:
            
            active_sessions = ue.get_active_sessions() 
            if len(active_sessions) < 1:
                return False
            session = random.choice(active_sessions)
            
            # Send downlink packets, if it fails, return False
            sent = session.downlink_traffic()
            if sent:
        
                # Check if the UE is now connected
                state_changed = ue.wait_state_change()
                if state_changed and ue.state == UEState.CONNECTED: 
                    return True
        
        return False

