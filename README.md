# PCAP-Threat-Analysis-Lab

## ftp.pcap - FTP Credentials Disclosure

## Tools Used
- Wireshark
- snort

## Threat Detected
- **Plaintext FTP Credentials**
- **Potential unauthorized access**
- **Evidence:** Username and password sent in cleartext, file transfer of `music.mp3`

## Key Details
- **Source IP:** 192.168.0.114
- **Destination IP:** 192.168.0.193
- **Username:** `csanders`
- **Password:** `echo`
- **FTP Command:** `USER`, `PASS` seen in cleartext
- **Transferred File:** `music.mp3` (uploaded or downloaded)
- **Port:** TCP 21


## Screenshots

![FTP Credentials in Wireshark](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/ftp-credentials.png)

## Custom Snort Rules (local.rules)

alert tcp any any -> any 21 (
    msg:"FTP USER command detected";
    content:"USER ";
    sid:1000001;
    rev:1;
)

alert tcp any any -> any 21 (
    msg:"FTP PASS command detected";
    content:"PASS ";
    sid:1000002;
    rev:1;
)

alert tcp any any -> any 21 (
    msg:"FTP anonymous login attempt";
    content:"USER anonymous";
    sid:1000003;
    rev:1;
)

## Rule Summary
SID	Description
1000001	Detects USER command
1000002	Detects PASS command
1000003	Detects anonymous login attempts

** rules file** : /etc/snort/rules/local.rules

## command used :
sudo snort -R /etc/snort/rules/local.rules -r ~/projects/projects/wireshark/credential_exposure/ftp.pcap -A alert_fast -c /etc/snort/snort.lua -l /tmp/

**output**:

12/16-13:24:40.504807 [**] [1:1000001:1] "FTP USER command detected" [**] [Priority: 0] {TCP} 192.168.0.114:1137 -> 192.168.0.193:21
12/16-13:24:40.507195 [**] [1:1000002:1] "FTP PASS command detected" [**] [Priority: 0] {TCP} 192.168.0.114:1137 -> 192.168.0.193:21

![alert by snort](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/snort_alert.png)

## Indicators of Compromise (IOCs)
Unencrypted FTP login (no SSL/TLS)
Credentials visible in raw packet payload
Anonymous login attempt detected
Insecure transfer of music.mp3

## Conclusion
FTP transmits sensitive credentials in plaintext.
Wireshark allowed deep inspection and verification of credential leakage.
Snort was successfully configured to detect both generic and specific FTP login attempts.
To prevent such exposures, use secure alternatives like FTPS or SFTP.


## arp.pcap - ARP packet inspection

## Tool 
- wireshark

## Thread detected :
- none

## Key points :

Packet | Type	  | Source MAC	           | Destination MAC	            | IP Info (from Info column)
ARP    | Request  |	HonHaiPrecis_6e:8b:24  | Broadcast (ff:ff:ff:ff:ff:ff)	| who has 192.168.0.1? Tell 192.168.0.114
ARP    | Reply	  | DLINK_0b:22:ba	       | HonHaiPrecis_6e:8b:24	        | 192.168.0.1 is at 00:13:46:0b:22:ba

## Screenshot :

![arp screenshot]()
![apr]()
![arp]()

## Indicators of Compromise (If Suspicious)

 Check whether the MAC address in the ARP reply is valid for that IP

- Look for signs of ARP spoofing:
- Unexpected MAC address
- Frequent ARP replies without requests (not in this PCAP but worth noting)

## Conclusion 

This PCAP contains a standard ARP resolution sequence.
No immediate threats are evident unless the ARP reply contains an incorrect or spoofed MAC address. If part of a larger traffic capture, consider running
a Snort rule to detect abnormal ARP behavior (e.g., unsolicited ARP replies).
