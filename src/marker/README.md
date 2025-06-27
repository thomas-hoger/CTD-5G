not perfect because :
- we edit values but let an incoherent checksum
    - would require to recaculate the checksum
- put a random mac that will be consistent in the context of an attack but not in regard to the whole traffic
    - if the value of the ip replaced was already used, in the cn or in another attack, the MAC wont match which is incoherent
    - would require to remember the list of used mac and fetch the one used by the legitimate CN