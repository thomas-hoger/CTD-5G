from src.utils.ueransim.ue import gNodeB

def test_gnb():
    gnbs = gNodeB.get_registered_gnb()
    assert len(gnbs) == 1
