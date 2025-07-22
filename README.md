# Control Traffic Dataset for 5G Networks (CTD5G)

<p align="center">
<img src="https://img.shields.io/badge/UERANSIM-v3.2.7-blue" />
<img src="https://img.shields.io/badge/free5gc--compose-v4.0.0-blue">
<img src="https://img.shields.io/badge/CTD5G-v1.0.0-blue">
</p>

## Introduction

This repository provides the community with tools to generate plausible 5G control‑plane traffic datasets. It accompanies a manuscript currently under review, which outlines the motivations, gaps in state‑of‑the‑art, and the methodologies we employ.

We offer both a tool and a transparent methodology, with the aim of establishing a common foundation for anomaly‑detection research. While this base may not cover every possible attack or surface, our intention is for it to be co‑evolutionary and allow the community to iteratively improve it in a coordinated direction.

The 2025 version of CTD‑5G has been published on Zenodo; please cite it using the following DOI and link:

```
    Hoger, T., OWEZARSKI, P., & Durand Nauze, G. (2025).
    Control Traffic Dataset for 5G Networks (CTD5G) (1.0) [Data set]. 
    Zenodo. https://doi.org/10.5281/zenodo.15853959
```

The dataset is organized into two main directories:

- **Benign Only**: Contains exclusively benign 5G control-plane traffic samples.
- **Mixed**: Contains both benign and attack traffic interleaved.

Each of these directories includes:
- The generated log files.
- Two subdirectories:
  - A **processed** (realistic) version of the dataset, suitable for training, evaluation, and benchmarking.
  - A **original** (raw) version, which retains internal artifacts used to distinguish between benign and malicious samples. This version is primarily intended for development, debugging, or validation.

The processing functions and their behavior are available in [`src/marker`](./src/marker).


## Current status

Development is currently ongoing. Three network surfaces are already well covered, both in terms of attacks and benign traffic. The next step involves implementing attacks targeting the access network.

| Network Surface            | Attacks | Benigns |
|---------------------------|:-------:|:-------:|
| Core Network Management   |   ✅    |   ✅    |
| Session Management        |   ✅    |   ✅    |
| User Traffic Encapsulation |   ✅    |   ✅    |
| Access Network            |   ❌    |   ✅    |
| Mobility Control          |   ❌    |   ❌    |
| Slicing                  |   ❌    |   ❌    |

## Supported features

Detailed descriptions are available in the [src/attacks](./src/attacks) and [src/benign](./src/benign) directories.

### [Benign procedures](./src/benign)

| **Procedure**        | **Access Network** | **SBI API** | **Session Management** | **Packet Forwarding** |
|----------------------|:------------------:|:-----------:|:-----------------------:|:----------------------:|
| Register UE          | ✅                 | ✅          | ✅                      |                        |
| Set UE Idle          | ✅                 | ✅          | ✅                      |                        |
| Uplink Wake          | ✅                 | ✅          | ✅                      |                        |
| Downlink Wake        | ✅                 | ✅          | ✅                      |                        |
| Restart Session      | ✅                 | ✅          | ✅                      |                        |
| Deregister UE        | ✅                 | ✅          | ✅                      |                        |
| Add NF               |                    | ✅          |                         |                        |
| Remove NF            |                    | ✅          |                         |                         |
| User Traffic         |                    |              |                         | ✅                     |

### [Attack procedures](./src/attacks)

| **Attack**                  | **Surface**             | **Development Status**        |
|:----------------------------|:------------------------|:------------------------------|
| CN MITM                     | CN API Call             | ✅ Implemented                |
| Applicative Scan            | CN API Call             | ✅ Implemented                |
| API Fuzzing                 | CN API Call             | ✅ Implemented                |
| Session Establishment Flood | Session Management      | ✅ Implemented                |
| Session Deletion Flood      | Session Management      | ✅ Implemented                |
| SEID Fuzzing                | Session Management      | ✅ Implemented                |
| Session Modify Drop         | Session Management      | ✅ Implemented                |
| Session Modify Duplicate    | Session Management      | ✅ Implemented                |
| Uplink Spoofing             | Packet Forwarding       | ✅ Implemented                |
| PFCP in GTP                 | Packet Forwarding       | ✅ Implemented                |
| Manipulate Session with AMF | CN API Call             | 🛠️ Work In Progress           |
| NF Registration Flood       | CN API Call             | 🛠️ Work In Progress           |
| DoS AMF with malformed NGAP | Access Network          | 📋 Not yet implemented        |
| UE Connect Inondation       | Access Network          | 📋 Not yet implemented        |
| Manipulate session with gNB | Access Network          | 📋 Not yet implemented        |
| Flood contexte release      | Access Network          | 📋 Not yet implemented        |
| Paging interception         | Access Network          | 📋 Not yet implemented        |
| RAN MITM                    | Access Network          | 📋 Not yet implemented        |
| Broadcast fake black-list   | Access Network          | 📋 Not yet implemented        |
| RRC State Change Flood      | User Equipments         | 📋 Not yet implemented        |
| Rogue UE replace legitimate | User Equipments         | 📋 Not yet implemented        |
| Silent Paging               | User Equipments         | 📋 Not yet implemented        |
| DoS UE with specific value  | User Equipments         | 📋 Not yet implemented        |
| Slice Pivoting              | Slicing                 | ⛔ Don't work                 |
| Downlink spoofing           | Packet Forwarding       | ⛔ Don't work                 |
| GTP-in-GTP                  | Packet Forwarding       | ⛔ Don't work                 |

## Installation

### Install the 5G CN and RAN simulator 
```
git clone https://github.com/thomas-hoger/free5gc-compose.git
cd free5gc-compose
docker compose up -d
cd ..
```
### Clone the 5GC API (required to use the fuzzing attack)
```
git clone https://github.com/jdegre/5GC_APIs.git
```
### Install the dataset generator
```
git clone https://github.com/thomas-hoger/CTD-5G.git
cd CTD-5G
pip install -r requirements.txt
cd ..
```

## Usage

> [!WARNING]
> A working 5G simulator is required to use this codebase. Please ensure the simulator is running before starting any experiments.

### Run the dataset generator
You can launch the generator using the CLI:
```
python run.py [-d DURATION (in minuts)] -t {benign,attack} 
```
Alternatively, use the provided bash script to run both benign and attack procedures in the background while capturing traffic with `tcpdump`
```
./run.sh
```
### Expected output
Logs are generated by the Python script to monitor the execution process. When using the bash script, logs are redirected to the `output` directory.

```
[Benign Traffic] [22:26:45] Running procedure 1: register_random_ue
Registering imsi-208930000000951
Procedure finished with result: ✅
Current UE states : UE-0569 😀, UE-0881 😀, UE-0951 😀
Current NFs : 3e638adc, 1c0a87cb
==============================
[Benign Traffic] [22:27:05] Running procedure 2: set_random_ue_idle
Setting UE imsi-208930000000569 to idle
Procedure finished with result: ✅
Current UE states : UE-0569 😴, UE-0881 😀, UE-0951 😀
Current NFs : 3e638adc, 1c0a87cb
```
This output includes : 
- The name and timestamp of the procedure
- Execution result (✅ or ❌)
- Current list of UEs and their states (😀 = Connected, 😴 = Idle)
- Registered NFs
- Additional debug information

### Unit tests
To validate modifications or review how individual procedures work, you can run unit tests:
```
python -m pytest
python -m pytest src/attacks/api_cn/tests
```

## Troubleshooting
### Making changes on the code
### Upgrading free5gc
### Upgrading ueransim 
### UE registration keeps failing
If UE registration repeatedly fails, it's often a sign that the **core network is not functioning properly**. This is often due to:
- A critical network function (NF) being down or misconfigured.
- The NRF (Network Repository Function) not responding or rejecting registrations and/or JWT creation.
- création de token oauth refusé par le NRF
Make sure all essential NFs are running and correctly registered with the NRF. You can check the current NF list and status using the `get_nf_info` function available in [`src/utils/protocols/api_cn/instance.py`](src/utils/protocols/api_cn/instance.py). 

## Licence
Copyright © 2025 CNRS-LAAS

This project is licensed under the [GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.en.html).

## Contact and credits

If you use this dataset, please cite it:
```
    Hoger, T., OWEZARSKI, P., & Durand Nauze, G. (2025).
    Control Traffic Dataset for 5G Networks (CTD5G) (1.0) [Data set]. 
    Zenodo. https://doi.org/10.5281/zenodo.15853959
```
If our paper helps your research, please cite:
```
(Paper in reviewing)
```

For any questions or issues, please contact thomas.hoger@laas.fr
