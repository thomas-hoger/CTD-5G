from src.utils.ueransim.ue import UserEquipment
from src.utils.ueransim.session import PDUSession
import pytest

@pytest.fixture(autouse=True)
def clear_ues():
    
    # Setup
    UserEquipment.terminate_all()
        
    # Execution
    yield 
    
    # Teardown 
    UserEquipment.terminate_all()
    

def test_registration():
    
    # ----- Initial State, no UE registered
    sessions = PDUSession.get_sessions()
    assert len(sessions) == 0
    
    # ----- Register 1 UE
    test_imsi = UserEquipment.get_available_imsi() # Get a random IMSI that is not currently registered
    test_ue:UserEquipment = UserEquipment.register_new(test_imsi)
                            
    sessions:list[PDUSession] = PDUSession.get_sessions()
    session:PDUSession = sessions[0]
    assert len(sessions) > 0
    
    # ---- Test traffic
    assert session.uplink_traffic(10, "google.com")
    assert session.downlink_traffic(10)
        
    # ----- Restart
    assert session.restart()
    
    # ----- Deregister UE
    test_ue.deregister()