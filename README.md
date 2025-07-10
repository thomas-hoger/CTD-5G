# Control Traffic Dataset for 5G Networks (CTD5G)

<p align="center">
<img src="https://img.shields.io/badge/UERANSIM-v3.2.7-blue" />
<img src="https://img.shields.io/badge/free5gc--compose-v4.0.0-blue">
<img src="https://img.shields.io/badge/CTD5G-v1.0.0-blue">
</p>

## Current status

Development is currently in progress, 3 surfaces are already relatively well covered, whether by attacks or benign traffic. The implementation of attacks targeting the access network is the next step and is currently underway.

<table align="center">
    <thead>
      <tr>
        <th>Network Surface</th>
        <th>Attacks</th>
        <th>Benigns</th>
      </tr>
    </thead>
    <tbody>
      <tr><td>Core Network Management</td><td>✅</td><td>✅</td></tr>
      <tr><td>Session Management</td><td>✅</td><td>✅</td></tr>
      <tr><td>User Traffic Encapsulation</td><td>✅</td><td>✅</td></tr>
      <tr><td>Access Network</td><td>❌</td><td>✅</td></tr>
      <tr><td>Mobility Control</td><td>❌</td><td>❌</td></tr>
      <tr><td>Slicing</td><td>❌</td><td>❌</td></tr>
    </tbody>
  </table>

## Installation

> [!WARNING]
> Installation of a 5G simulator is absolutely mandatory to use our code, please verify that the your simulator is running before starting the experimentation. 

### Install the 5G CN and RAN simulator 
```
git clone https://github.com/thomas-hoger/free5gc-compose.git
cd free5gc-compose
docker compose up -d
```
### Install the dataset generator
```
git clone https://github.com/thomas-hoger/CTD-5G.git
cd CTD-5G
pip install -r requirements.txt
```

## Usage
### Run the dataset generator
The generator can be launcher via the CLI run.py
```
python run.py [-d DURATION (in minuts)] -t {benign,attack} 
```
A bash script is also available to start both the benign and attacks as background tasks and to sniff the traffic with tcpdump.
```
./run.sh
```
### Expected output
The python executable produces logs that are useful for analyzing the generator's operation. If you run the executable with the bash script, the logs will be redirected to ./output/

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
This output shows : 
- The name of the procedure and the timestamp at which it have been executed
- Boolean success result of the procedure {✅, ❌}
- The current list of registered UEs with their current state {Connected: 😀, Idle: 😴}
- The current list of registered NFs
- Additionnal informations about the procedure execution
### Unit tests
Unit tests are also available if you're modifying code and want to make sure that it's working properly, or if you want an example of how to use procedures individually. They can be launched together or individually by precising the path of the file/or folder.
```
python -m pytest
python -m pytest src/attacks/api_cn/tests
```

## Supported features

<table style="text-align: center;">
    <thead>
      <tr>
        <th style="text-align: center;">Attacks</th>
        <th style="text-align: center;">Benigns</th>
      </tr>
    </thead>
    <tbody>
      <tr><td>Fuzz</td><td>Register UE</td></tr>
      <tr><td>CN MITM</td><td>Restart Session</td></tr>
      <tr><td>SEID Fuzzing</td><td>User Traffic</td></tr>
      <tr><td>Flood Establishment</td><td>Set UE Idle</td></tr>
      <tr><td>Flood Deletion</td><td>Uplink Wake</td></tr>
      <tr><td>Applicative Scan</td><td>Deregister UE</td></tr>
      <tr><td>Modify Duplicate</td><td>Downlink Wake</td></tr>
      <tr><td>Modify Drop</td><td>Add NF</td></tr>
      <tr><td>Uplink Spoofing</td><td>Remove NF</td></tr>
      <tr><td>PFCP in GTP</td><td></td></tr>
    </tbody>
  </table>

## Common issues
### Making changes on the code
docker compose build --no-cache
### Upgrading free5gc
### Upgrading ueransim 

## Licence
Copyright © 2025 CNRS-LAAS

All source code and related files including documentation and wiki pages are licensed with [GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.en.html).

## Contact and credits

If you use our dataset, please cite it:
```
(Zenodo publication in progress)
```
If you find our paper useful, please cite it:
```
(Paper in reviewing)
```

For any questions or issues, please contact thomas.hoger@laas.fr
