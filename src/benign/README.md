# Benign Procedures — CTD5G Dataset

## Overview
This document provides a comprehensive overview and detailed usage information for the benign network procedures included in the CTD5G (Control Traffic Dataset for 5G Networks) project.

Benign procedures simulate normal and legitimate operations within 5G core and access networks, serving as essential baseline behaviors for traffic generation. These baselines enable effective differentiation between typical network activity and potential malicious actions.

While user traffic content is generally encrypted and less specific to 5G, control traffic is highly diverse and reflects mechanisms unique to mobile networks, some of which are specific to 5G. This control traffic consists of well-defined signaling procedures, composed of sequences of signaling messages exchanged among multiple network entities. Each signaling message performs a specific function, contributing to the overall operation and management of the 5G network.

Importantly, individual procedures can generate traffic across multiple network surfaces. For anomaly detection purposes, it is crucial to cover a wide variety of signaling procedures and network surfaces to capture the full diversity of messages and behaviors within the network.

> [!WARNING]
> The procedures triggered by `run.py` are selected randomly from a predefined list of benign operations. However, some procedures require specific preconditions to be valid. For example, state transitions depend on the current UE status: waking up a UE requires it to be in the `IDLE` state, while releasing a session requires it to be `CONNECTED`. These procedures are automatically excluded from the candidate list if their execution conditions are not met. The full list of benign procedures and their logic can be found in [`src/benign/procedures.py`](src/benign/procedures.py).

## UE Registration and Deregistration
Procedures relative to the UE are defined in [`src/utils/ueransim/ue.py`](src/utils/ueransim/ue.py). The UERANSIM CLI is used to connect and disconnect User Equipments (UEs). One challenge is that registration and deregistration **processes are asynchronous** and can take a variable amount of time to complete. To handle this, we have implemented helper functions that wait for the process to finish, with a timeout mechanism to prevent indefinite blocking.

It is also important to never launch two instances with the same IMSI simultaneously, as the most recent instance will inevitably fail. The deregistration procedure in UERANSIM generates signaling messages and is useful; however, it does not fully disconnect the UE. Therefore, it is necessary to terminate the UE process manually to prevent it from automatically reconnecting to the Core Network.

If the UE launch process is interrupted or takes too long, the underlying `ueransim` executable may still be running in the background. To prevent orphan processes and potential inconsistencies, a timeout mechanism is in place. If the UE fails to complete registration within the expected time window, it is:
- Explicitly deregistered from the network if necessary
- Forcefully terminated to clean up the `ueransim` process
This ensures the system remains stable and avoids resource leaks. For custom timeout configurations or cleanup behavior, refer to the relevant logic in [`src/ue/launcher.py`](src/ue/launcher.py) (or wherever your timeout logic lives).

> [!WARNING]
> To register a UE, the IMSI used in the UERANSIM CLI must be pre-registered in the Core Network database. We provide a function in [`src/utils/ueransim/database.py`](src/utils/ueransim/database.py) that can automatically add a large range of IMSIs to the database. Please ensure that you have at least some registered IMSIs before attempting to register a UE.

## UE State Switching
When a UE remains inactive for a certain period, the gNB can request the core network to transition the UE into idle mode. This request is called a **context release** and we permform it using the UERANSIM CLI. 

There are two ways to trigger the context restoration:
- The first, called **service request**, consists of generating uplink traffic. In our case, we ping from the UE through one of the PDU session tunnels to an arbitrary internet address.
- The second, called **paging**, consists of sending downlink data. For this, we ping the UE from the UPF through the interface that connects them.
These two methods generate slightly different message sequences.

However, at the time of writing, the existing UERANSIM version did not work properly with context release, which made session restoration impossible. Therefore, I had to fork UERANSIM and use a modified version within the free5gc Docker environment. A detailed description of the issue and the resolution method can be found here: [`UERANSIM Issue #757`](https://github.com/aligungr/UERANSIM/issues/757).

As with UE registration and deregistration, since the process is asynchronous, it is necessary to verify that the UE state in UERANSIM has indeed changed before proceeding.

## Session Management
By default, launching a UE with `ueransim` creates **two PDU sessions**, as defined in its YAML configuration. While this behavior can be customized via the YAML file, **we have kept the default setup** in our implementation.

A more dynamic behavior would involve the UE staying connected to the core network while creating or releasing PDU sessions over time. Our goal is to eventually support this model, where each UE maintains a live list of active sessions and can add or remove them on demand.

However, in practice, implementing this has proven challenging. In particular, released sessions are often **automatically re-established** by `ueransim`. As a workaround, instead of dynamically managing session states, we provide a function that **restarts** a session and waits until it is fully re-established.

To do this, we use `ueransim`’s built-in `ps-release` command with the session number as an argument. One tricky aspect is that this session number is **assigned by the gNB** and is completely **independent from the session ID used by the UE**, which adds complexity when tracking sessions.

> [!NOTE]
> Several benign and attack procedures depend on having at least one active PDU session (e.g., uplink/downlink traffic, uplink spoofing, PFCP injection via GTP). We ensure that **at least one session is always running** before attempting such operations.

Relevant implementation details can be found in  
[`src/utils/ueransim/session.py`](src/utils/ueransim/session.py).

## NF Management
Adding or removing Network Functions (NFs) is a common operation during both **startup and shutdown**, but it can also occur **dynamically at runtime**. Thanks to the flexible nature of 5G architecture, the core network can scale or adapt based on traffic conditions or system changes.

To simulate this dynamic behavior, we **artificially add and remove NFs** while ensuring the continuity of network operation. This is particularly useful for testing robustness and observing system responses under load or topology changes.

We manage a list of NFs registered by our own system, maintained in  
[`src/utils/protocols/api_cn/instance.py`](src/utils/protocols/api_cn/instance.py).  
Only NFs from this list are eligible for removal, ensuring we don't interfere with critical or statically defined services.

New NFs are registered via `PUT /nnrf-nfm/v1/nf-instances` requests to the **NRF**, using `httpx` (for HTTP/2 support) instead of `requests`. For each new NF, we randomly:
- Select a **NF type** (e.g., SMF, UDM, AUSF)  
- Assign a unique **instance ID**
- Choose a coherent set of **services** based on the NF type
- Allocate an **IP address** from the pool of available network IPs

> [!WARNING]
> Another limitation of our current implementation is that all NF `create` and `delete` requests are sent from the **host machine**, meaning they always originate from the same IP address.  
> This is **not realistic**, since in real-world deployments, each NF registers itself using its own IP — the one it uses in the data plane. In our case, we're using the `httpx` library (to support HTTP/2), but as far as we know, it does **not support custom source IP binding**.
> A possible improvement would be to **spoof the source IP** at the packet level using tools like **Scapy**, which would allow us to match the source IP to the NF instance being registered. However, this introduces more complexity and is currently left as **future work**.


## Packet Forwarding
Although the user plane payload is encrypted and offers limited visibility, its forwarding relies on **GTP-U encapsulation**, a protocol specific to mobile network data transport. Since several documented attacks exploit flaws in GTP-U handling, we include a representation of normal GTP-U usage to better model and analyze network behavior.

To simulate this, we simply launch `ping` requests from the UE to the data network (DN), using the dedicated interface tied to a randomly selected **PDU session**. By routing traffic through this interface, the packets are automatically encapsulated in GTP-U headers before leaving the UE.

The same logic is used for generating uplink traffic. You can find the implementation in [`src/utils/ueransim/session.py`](src/utils/ueransim/session.py).
