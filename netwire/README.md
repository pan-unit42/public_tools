![](https://paloaltonetworks.com/content/dam/paloaltonetworks-com/en_US/images/logos/brand/PANW_Unit42_Logo.png)
# NetWiredRC Decoder

Based on the malware seen in the Unit 42 [419 Evolution](http://connect.paloaltonetworks.com/adversary-report) research paper this tool will decrypt the traffic using the netwire protocol.

```
 $ python netwire_decode.py -h
usage: %prog [OPTIONS] [-h] [-P Password] [-f] [-p] [-i]

decode netwire traffic based on key exchange packets

optional arguments:
  -h, --help            show this help message and exit
  -P Password, --password Password
                        password used to create AES key
  -f , --file           pcap file to parse
  -p , --port           port that netwire server is on
  -i , --ip             ip address that netwire client is on
```
