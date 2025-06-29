pfcp_in_gtp : ok -> what do we put in the pfcp ? make it variable

uplink_spoofing : ok 

downlink_spoofing : ko -> The downlink GTP attack doesn't work because Free5GC includes a security check that verifies whether the IP address in the packet matches what is expected based on the session context. Specifically, it uses the PDR (Packet Detection Rule) direction to determine if the packet's source or destination IP matches the UE's IP. If the packet comes from an unknown source or isn't part of an established session, it gets dropped. As a result, only legitimate responses to existing sessions are forwarded, and fake or unsolicited downlink packets are blocked.

gtp_in_gtp : ko -> can't work for the same reason

session modif : we make the assumption that the attacker already found the seid and valid far_id another way (like for example with a previous seid fuzzing)

5GAD says it's possible to do an nrf discovery without giving an nf_type and that it's supposed to return all NFs. Maybe on their implementation and 5G version it worked, but with free5gc it doesn't work now.