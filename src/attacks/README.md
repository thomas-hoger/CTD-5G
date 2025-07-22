<<<<<<< HEAD
pfcp_in_gtp : ok -> what do we put in the pfcp ? make it variable

uplink_spoofing : ok 

downlink_spoofing : ko -> The downlink GTP attack doesn't work because Free5GC includes a security check that verifies whether the IP address in the packet matches what is expected based on the session context. Specifically, it uses the PDR (Packet Detection Rule) direction to determine if the packet's source or destination IP matches the UE's IP. If the packet comes from an unknown source or isn't part of an established session, it gets dropped. As a result, only legitimate responses to existing sessions are forwarded, and fake or unsolicited downlink packets are blocked.

gtp_in_gtp : ko -> can't work for the same reason

session modif : we make the assumption that the attacker already found the seid and valid far_id another way (like for example with a previous seid fuzzing)

5GAD says it's possible to do an nrf discovery without giving an nf_type and that it's supposed to return all NFs. Maybe on their implementation and 5G version it worked, but with free5gc it doesn't work now.
=======
# Attacks — CTD5G Dataset

## Overview
This document provides an overview and detailed description of the attack procedures included in the CTD5G (Control Traffic Dataset for 5G Networks) project.

Attack procedures simulate malicious or abnormal behaviors targeting the 5G core and access networks. These attacks are designed to exploit vulnerabilities or misconfigurations in network functions, protocols, or session management mechanisms. They serve as critical examples for evaluating detection and mitigation techniques against 5G network threats.

Unlike benign traffic, attack traffic often aims to disrupt normal operations, cause denial of service, intercept or manipulate data, or compromise network integrity. Despite this, some attacks carefully mimic legitimate signaling patterns to evade detection, making their identification challenging.

The attacks span multiple layers and functionalities of the 5G network, including API misuse, session manipulation, man-in-the-middle scenarios, and user plane packet forwarding exploits. Each attack procedure focuses on a specific vulnerability or threat model, generating traffic that reflects realistic adversarial behavior.

## API calls in the CN

Toutes les attaques du CN nécessitent l’enregistrement d’une Network Function (NF) pour obtenir un token JWT. De plus, il est souvent nécessaire de connaître la liste des NF déjà enregistrées dans le NRF.

Pour cela, nous avons mis en place trois fonctions principales : `NF registration`, `JWT acquisition`, et `discovery requests`, toutes définies dans [`src/utils/protocols/api_cn/instance.py`](src/utils/protocols/api_cn/instance.py). Ces fonctions utilisent la bibliothèque `httpx` pour gérer les interactions HTTP avec le NRF.

> [!WARNING]
> All API-based attacks on the core network require registering a network function (NF) and obtaining a JWT token for it. In the case of an attacker sending only a few requests, there's no need to remove the NF afterward. However, since our attack scenarios involve looping requests over several hours, this can eventually overload the NRF and lead to a denial of service. To avoid this, we ensure that our NFs are removed at the end of each attack.

### Applicative NF scanning ✅
In 5G networks, network functions (NFs) are dynamically registered and discovered via the NRF. The NRF maintains a list of all active NFs and their descriptions. When a function needs a service, it queries the NRF to discover other NFs that offer it. [5GAD](https://github.com/IdahoLabResearch/5GAD) highlights that if authentication is weak or misconfigured, an attacker can exploit the discovery interface to infer the topology of the core network. 

To simulate this attack in practice, the following steps are performed:

1. **Register a rogue NF:**  
   A fake NF instance is added to the network. This step is required to obtain credentials and appear legitimate to the NRF.

2. **Obtain a JWT token:**  
   A token is requested on behalf of the rogue NF with the `nnrf-disc` scope, allowing it to query the discovery API.

3. **Perform NF discovery:**  
   A `GET /nnrf-disc/v1/nf-instances` request is made, optionally specifying an NF type to search for. The query uses URL-encoded parameters to indicate the desired NF type.

   - **Targeted discovery (discreet):**  
     The attacker selects a list of legitimate NF types and performs one discovery per type. These requests mimic real usage patterns and are less likely to trigger alarms.

   - **Broad discovery (suspicious):**  
     5GAD mentions it is technically possible to send a discovery request without specifying any NF type (i.e., a "GetAllNFs" query). This would return all registered NFs of all types. However, this behavior does **not** work in Free5GC. This type of message is not expected in legitimate network traffic, making it highly suspicious and easy to detect.

> [!NOTE]
> Although broad discovery (GetAllNFs) may fail depending on implementation (e.g., Free5GC), it still represents a likely attacker intent and a clear anomaly in control traffic patterns.

### API fuzzing ✅
5G networks follow standardized specifications from 3GPP, which define a set of APIs that all compliant network functions (NFs) must expose. These API definitions are public and well-documented, making it easy for attackers to understand the expected request structure, parameters, and behaviors. Some open-source initiatives, such as [jdegre/5GC_APIs](https://github.com/jdegre/5GC_APIs), have extracted these specifications and published them as Swagger/OpenAPI documents. These resources make it easier to programmatically explore all available endpoints, their methods, expected parameters, and value patterns.

The core idea of API fuzzing is to send crafted requests with valid syntax but forged or boundary-value data. These requests pass superficial validation but may trigger unexpected behavior deeper in the implementation logic.

1. **Obtain Swagger/OpenAPI specs:**  
   YAML files from sources like `jdegre/5GC_APIs` are used to identify endpoints, HTTP methods, and expected parameter structures.

2. **Parse API structure:**  
   The parser extracts:
   - URI paths
   - HTTP methods (e.g., GET, POST, DELETE)
   - Parameters (query, path, body) and their types or patterns

   > [!NOTE]
   > In practice, parameter schemas often reference external files or other components in the OpenAPI tree. Our current parser is simplistic and often fail to resolve these nested references. Improving this recursive resolution would significantly enhance the attack coverage.

3. **Select fuzzing strategy:**  
   Two approaches are possible:
   - **Full parameter set:** Fill in all fields (required and optional).
   - **Minimal set:** Use only required fields to mimic realistic calls.

4. **Register rogue NF and obtain JWT:**  
   As with discovery attacks, the attacker must first register a fake NF and obtain a valid JWT token with sufficient privileges to call other NF services.

5. **Send forged requests:**  
   Using the parsed API descriptions, the attacker sends validly structured but malicious requests to different endpoints.

Although the requests are technically valid from a schema point of view, most will be rejected by actual implementations due to missing context, permissions, or sanity checks. Nonetheless, this technique represents a plausible and stealthy attack vector and could evolve into a more sophisticated method with improved logic and better schema parsing.

The parsing and request logic is implemented in [`src/utils/api_fuzzer/parser.py`](src/utils/api_fuzzer/parser.py).

### Applicative Man-in-the-middle ✅
In 5G core networks, when a discovery request is made to locate a network function providing a particular service, the NRF returns a list of all available instances. If no proper authentication is enforced, an attacker present in the core network can register a rogue NF claiming to offer the desired service. It will then appear in the discovery responses alongside legitimate NFs.

In **free5GC**, the receiving NF often selects the oldest registered instance. The attacker can remove and re-add all other legitimate NFs, making their rogue NF the oldest and thus selected first. By transparently forwarding the intercepted traffic to the correct destination (e.g., using `socat`), the attacker can inspect or alter it — even if it's TLS-protected — without disrupting service.

To avoid a denial of service, it is critical to re-register each removed NF with its exact original parameters: NF ID, NF type, IP address, and supported services. These must be saved during the initial discovery phase.

The full setup sequence is as follows:
1. Add a fake NF with random parameters to send the initial requests
2. Request a JWT token for this NF
3. Choose the target NF type to impersonate
4. Perform a discovery to get the list of existing NFs of this type and store all their parameters
5. Deregister all these NFs from the NRF
6. Register a rogue NF of the same type (now appearing as the oldest)
7. Re-register the legitimate NFs with the exact same parameters
8. Use a `socat` command to forward all incoming traffic from the rogue NF to the original legitimate NF

To stop the attack, simply deregister the rogue NF from the NRF.

> [!NOTE]
> The order of steps 4 to 6 is not strictly mandatory and the MITM NF can be added before removing the legitimate ones.

## Session manipulation

All session-based attacks use Scapy along with the PFCP layer, which is defined in `scapy.contrib`. To avoid crafting packets from scratch every time, our attacks rely on helper code located in [`src/utils/protocols/pfcp/pfcp.py`](src/utils/protocols/pfcp/pfcp.py). These attacks require a sequence number, and it is critical that this number is different for each request.

> [!INFO]  
> In free5GC, most PFCP messages we've tested return "Request Accepted" even if the action was not actually successful. This was confirmed by analyzing internal logs. For example, sending a delete request for a non-existent session will still return an "Accepted" response, even though no session was actually deleted.

> [!WARNING]  
> All of our session attacks are performed using Scapy. As of this release, we haven’t been able to use `sr()` or similar Scapy functions to receive responses and verify what the network actually replies. As a result, most of our attack functions simply return `true` if the message was sent, without checking for a response—let alone validating its content.

### Session Establishment flooding ✅
[Amponis et al.](https://ieeexplore.ieee.org/document/10176693) propose to flood the UPF with a large number of session establishment requests. The goal is to saturate its buffers and exhaust its processing power and memory.

> [!NOTE]  
> It is essential to first send a PFCP Association Setup Request to the UPF. Without this initial association, the subsequent session establishment requests will not be processed.

### Session Deletion flooding ✅
In this attack, [Amponis et al.](https://ieeexplore.ieee.org/document/10176693) propose to cut the connection between the UE and the DN by sending deletion requests. Using this type of request, the UE is not disconnected from the AN or the CN and still appears connected. The attacker can either target a specific UE if they know its Session Identifier (SEID), or flood the network with session deletion requests varying the SEIDs to DoS as many UEs as possible.

Since a single deletion request is not inherently problematic and therefore extremely hard—if not impossible—to detect, our implementation simply performs flooding by randomly varying the SEID. The goal is to hit active UEs by chance. While this approach is not particularly effective, it still represents a plausible attack scenario where the attacker is focused on causing random damage or denial of service.

### Session modification ✅
[Amponis et al.](https://ieeexplore.ieee.org/document/10176693) propose two session modification attacks that target the UPF’s forwarding rules:
- The **drop attack** modifies the session to discard all packets, silently cutting off communication with the DN without alerting the UE.
- The **duplicate attack** changes the forwarding rule so that all packets are both sent to the legitimate destination and duplicated to an attacker-controlled address.

These packets are rarely seen in normal network operations, making them more easily detectable than deletion requests. As such, we assume the attacker already knows a valid SEID to target. Unlike the drop packet, the duplicate packet must include a `FORWARD` flag and define an `Outer Header Creation` IE to specify where to send the duplicated packets.

Modification packets are relatively complex. The key difference between the drop and duplicate versions lies in the packet flags. The **duplicate** version also requires the creation of an **Outer Header Creation** IE to specify the destination for the duplicated traffic.s The DUPL (duplicate) packet must also include a **FORWARD** flag for the modification to work as expected.

> [!WARNING]  
> In Free5GC, FAR IDs are assigned globally and can’t easily be predicted. Our current dataset uses a fixed FAR ID (1), which usually doesn't match the actual session’s FAR. So, the modification doesn't really apply — but since the network still replies with "Request Accepted," the behavior appears successful in traces. 

> [!TIP]  
> To make the attack actually work in the dataset, we could either sniff PFCP packets to track the FAR IDs assigned to each session, or implement a probing mechanism that sends harmless modification requests and analyzes the responses to discover valid FAR IDs dynamically.


### SEID fuzzing ✅
Some session attacks, like deletion or modification, require targeting a valid session. If the attacker doesn't know a correct SEID, they can brute-force it by sending many requests with different SEIDs. But if they hit a valid one and modify its state, it may disrupt the UE's connection and reveal the attack.

To avoid this, the attacker can send harmless modification requests that keep the session rules unchanged (e.g., a session modification with a FORWARD flag). If the SEID is valid, the network responds positively, allowing the attacker to detect active sessions without affecting them.

This method is stealthier and easier in Free5GC, where SEIDs are assigned incrementally starting from 1.


## Packet forwarding 
All packet forwarding based attacks use Scapy along with the GTP layer, which is defined in `scapy.contrib` These attacks also require a sequence number, and it is critical that this number is different for each request.

### PFCP in GTP ✅
[Park et al.](https://ieeexplore.ieee.org/document/9810284) present a vulnerability in the UPF decapsulation process related to forwarded messages. When a user sends data to the DN, it is encapsulated in a GPRS Tunneling Protocol (GTP) layer and passes through the UPF. The UPF decapsulates the packet, recognizes the underlying IP layer, and forwards it to the DN. However, in some 5G implementations such as free5GC, the UPF does not verify that the underlying layer is actually IP and interprets it regardless.

In the current situation, it is possible to send any kind of message from the UE, even if they are normally used only for session management, the UPF will still process them as valid. This is very serious and allows the UE to perform any kind of attack as if it were directly part of the core network, which is otherwise a very rare and critical assumption.

To do this, we simply encapsulate a packet of any type inside a GTP layer. Currently, we use an Association Setup message, but in the future, we could generalize this to include other types of content.

> [!WARNING]  
> This attack involves sending a message from a UE to the UPF, which requires both an available UE and an active session with a valid TEID. If the attack is launched without these prerequisites, the message will never reach the UPF.

> [!INFO]  
> Currently, we put PFCP inside the GTP layer, but since the UPF interprets the content, in theory this could work with any type of message. For example, one could put GTP inside GTP to target a UE (which does not work on free5GC) or HTTP/2 to simulate sending an API request coming from another NF.


### Uplink spoofing ✅
In their blog post, [Trend Micro](https://www.trendmicro.com/vinfo/us/security/news/internet-of-things/plague-private-5g-networks) presents a packet reflection vulnerability in the GTP protocol. Without proper validation, an attacker with access to the UPF can send a crafted GTP packet that encapsulates an IP packet falsely claiming to originate from a legitimate UE and targeting an external server. When the UPF receives it, it decapsulates the packet and forwards the spoofed IP packet to the Internet. This allows the attacker to impersonate the UE and perform malicious actions on its behalf. As a result, the legitimate UE may face service restrictions for actions it did not initiate — such as being banned from certain websites or services after a spoofed flood attack.

In our implementation, the attack uses ICMP packets (ping) in the inner IP layer, but this could easily be replaced with HTTP requests to specific sites or any other type of payload. This technique can also be combined with the PFCP-in-GTP attack to further obscure the source and intent of the traffic.

The packet we generate has two key layers:
- An **outer IP header** that sends the packet from the attacker to the UPF using the GTP protocol. 
- An **inner IP header** that pretends to come from the UE and targets an external server in the Data Network. 

This allows the attacker to send traffic that appears to originate from a legitimate UE, abusing the trust placed in GTP traffic by the UPF.


### Downlink spoofing ⛔
The downlink GTP attack does not work on Free5GC due to an internal security check implemented in its GTP-U handling code. Specifically, Free5GC verifies whether the IP address in the packet matches the expected value based on the session context. It uses the direction defined in the PDR (Packet Detection Rule) to determine whether to match the UE address with the source or destination IP of the incoming packet.

If the packet originates from an unexpected source or is not part of an established session, it is dropped. As a result, only legitimate downlink traffic associated with valid sessions is forwarded, while fake or unsolicited packets are blocked. This behavior is hardcoded in the Free5GC GTP5G module:

> ```c
> // This function checks whether an IP matches.
> // It uses the PDR direction to decide matching UE address
> // with the src address or dst address of receving packet.
> // If it is matched, it returns True; otherwise, it returns False.
> bool ip_match(struct iphdr *iph, struct pdr *pdr)
> ```

[Source - Free5GC `pdr.c`](https://github.com/free5gc/gtp5g/blob/3b9166f29812b9613447225d10beb28ef087cf4c/src/pfcp/pdr.c#L257)

### GTP in GTP ⛔
Same reason as the downlink spoofing: we can’t send a message to the UE unless it is a direct response.





>>>>>>> caef01f294b50ba72c371bb5f61348b71c78d995
