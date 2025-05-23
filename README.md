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

## Threat detected 
- none

## Key Details 

Packet | Type	  | Source MAC	           | Destination MAC	            | IP Info (from Info column)
ARP    | Request  |	HonHaiPrecis_6e:8b:24  | Broadcast (ff:ff:ff:ff:ff:ff)	| who has 192.168.0.1? Tell 192.168.0.114
ARP    | Reply	  | DLINK_0b:22:ba	       | HonHaiPrecis_6e:8b:24	        | 192.168.0.1 is at 00:13:46:0b:22:ba

## Screenshot 

![arp screenshot](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/arp.png)

![apr](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/arp1.png)

![arp](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/arp2.png)

## Indicators of Compromise (If Suspicious)

 Check whether the MAC address in the ARP reply is valid for that IP

- Look for signs of ARP spoofing:
- Unexpected MAC address
- Frequent ARP replies without requests (not in this PCAP but worth noting)

## Conclusion 

This PCAP contains a standard ARP resolution sequence.
No immediate threats are evident unless the ARP reply contains an incorrect or spoofed MAC address. If part of a larger traffic capture, consider running
a Snort rule to detect abnormal ARP behavior (e.g., unsolicited ARP replies).

## msnms.pcap - MSN Messenger PCAP Analysis

## Tool
- wireshark

## Threat Detected
- Unencrypted Instant Messaging Communication via MSN Messenger Protocol (msnms).
- Sensitive data such as usernames and messages were observed in cleartext, indicating potential privacy exposure if intercepted over an insecure network.

## Key Details

Message Type  |  Description
USR           |  Identify the user logging in. eg. USR 93 tesla_brian@hotmail.com Brian
CAL           |  Session or call initiation
JOI           |  A user has joined a session
MSG           |  Message exchanged between users

## Screenshots 

![USR](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/filterUSR.png)

![CAL](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/filterCAL.png)

![JOI](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/filterJOI.png)

![MSG](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/filterMSG.png)

![stream](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/msg1.png)

![stream](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/msg2.png)

![stream](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/msg3.png)

![stream](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/msg4.png)

## Indicators of Compromise (IOCs)

- Email addresses visible in plain text
- Chat contents exposed without encryption
- Session metadata like joins and initiations captured

## Conclusion 
The analysis confirms that MSN Messenger transmits critical information—such as usernames and chat messages—without encryption. 
This makes it highly susceptible to packet sniffing and man-in-the-middle attacks. It is strongly advised to avoid legacy IM services like MSN and use encrypted communication platforms.

## blaster.pcap - Blaster Worm

## Tool 
- Wireshark

## Treat Detected
Blaster Worm (MSBlast.exe) – A well-known worm targeting Microsoft Windows systems by exploiting the DCOM RPC vulnerability (MS03-026).

## Key Details 

Infection Method	         DCOM RPC Exploit
Backdoor Port Used	         TCP 4444
Affected Host (Victim)	     10.234.2.116 of packets using TCP port 4444 as source
Attacker Host	             10.234.0.239 IP of same packets (initiated the connection)
Command Observed	         start msblast.exe
Payload Location	         C:\WINNT\system32\msblast.exe
Exploit Action	             Remote shell access opened via port 4444

## Screenshot 

![blaster worm](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/blaster-worm.png)

## Indication of Compromise (IOCs)

- TCP communication on port 4444 (unusual backdoor activity)
- msblast.exe process execution command observed in cleartext
- Reverse shell behavior initiated from external host

# Conclusion
The blaster.pcap file contains evidence of a classic Blaster worm infection. The host with TCP port 4444 open is acting as the backdoor and is therefore the victim.
The presence of the start msblast.exe command confirms post-exploitation control. This is a clear example of malware behavior following exploitation of the MS03-026 vulnerability.
