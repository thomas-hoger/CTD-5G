from src.utils.ueransim.ue import UserEquipment, UEState
from src.utils.ueransim.gnb import gNodeB
import pytest

@pytest.fixture(autouse=True)
def clear_ues():
    """Kill every ue process before and after each test."""
    
    gnbs = gNodeB.get_registered_gnb()
    assert len(gnbs) > 0, "No GNBs registered, please start the UERANSIM container first."
    
    # Setup
    UserEquipment.terminate_all()
    
    # Execution
    yield 
    
    # Teardown 
    UserEquipment.terminate_all()
    

def test_registration():
    
    # ----- Initial State, no UE registered
    initial_ues = UserEquipment.get_registered()
    assert len(initial_ues) == 0 # No UEs should be registered initially
    
    known_imsis = UserEquipment.get_known_imsi()
    assert len(known_imsis) > 0 # Some imsi should be in the known database
    
    # ----- Register 1 UE 
    test_imsi = UserEquipment.get_available_imsi() # Get a random IMSI that is not currently registered
    assert test_imsi in known_imsis and test_imsi not in initial_ues
    
    test_ue:UserEquipment|None = UserEquipment.register_new(test_imsi)
    assert test_ue is not None # UE should be registered successfully
    assert test_ue.imsi == test_imsi # Registered UE should have the correct IMSI
    assert len(test_ue.sessions) > 0
        
    registered_ues = UserEquipment.get_registered()
    assert len(registered_ues) == len(initial_ues) + 1 # One more UE should be registered
        
    # ----- De-register 1 UE 
    assert test_ue.deregister() # De-registration should be successful
        
    registered_ues = UserEquipment.get_registered()
    assert len(registered_ues) == len(initial_ues) # After de-registration, the count should be back to initial state
   
def test_state():
    
    # ----- Register 1 UE
    test_imsi = UserEquipment.get_available_imsi() 
    test_ue:UserEquipment|None = UserEquipment.register_new(test_imsi)
    assert test_ue is not None
        
    # ----- Initial state check
    status = test_ue.get_status() # Query the status of the registered UE from the point of view of UERANSIM
    assert UEState(status) == test_ue.state # The state should match the registered UE state
    
    idle_ues = UserEquipment.get_idle_ues()
    assert len(idle_ues) == 0 # No idle UEs should be present initially
    
    connected_ues = UserEquipment.get_connected_ues()
    assert len(connected_ues) == 1 # One connected UE should be present
    
    # ----- Change the state to IDLE
    assert test_ue.context_release() # Context release should be successful
    assert len(UserEquipment.get_idle_ues()) == 1 

    # ----- Uplink wakeup
    assert test_ue.uplink_wake(session_id=0, packet_quantity=1, dn_domain="google.com") # Uplink packets to wake up the UE
    assert len(UserEquipment.get_idle_ues()) == 0 
    
    # ----- Change the state to IDLE again
    assert test_ue.context_release() # Context release should be successful
    assert len(UserEquipment.get_idle_ues()) == 1 
    
    # ----- Downlink wakeup
    assert test_ue.downlink_wake(session_id=0, packet_quantity=1) # Downlink packets to wake up the UE
    assert len(UserEquipment.get_idle_ues()) == 0 

    # ----- Restore initial state
    assert test_ue.deregister() # De-registration should be successful