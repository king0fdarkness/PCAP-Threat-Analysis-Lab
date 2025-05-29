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

## portscan.pcap - Portscanning Detection 

## Tool 
- Wireshark

## Treat Detected 
TCP SYN Port Scan
A single host is attempting to identify open ports on another host by sending multiple SYN packets across a range of port

## Key Details

Attacker IP : 10.100.25.14
Victim IP : 10.100.18.12
Number of syn packet : 29
Destination port scaned : multiple

## Screenshot

![syn packet](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/portscan1.png)

![packet details](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/portscan4.png)

![conversation](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/portscan2.png)

![endpoint](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/portscan3.png)

## Indication of Compromise (IOCs)

- Repeated SYN packets from 10.100.25.14 to 10.100.18.12
- Varying destination ports
- No corresponding SYN-ACK replies in some cases
- Typical signs of horizontal scanning

## Conclusion

This behavior indicates a reconnaissance attempt by the attacker to find open services on the victim. Continuous scanning like this can be a precursor to exploitation or intrusion.

## evilprogram.pcap - Suspicious HTTP Malware Activity

## Tool 
- Wireshark

## Threat Detection
Unauthorized system profiling via HTTP
Potential Command and Control (C2) communication
Use of legitimate-looking HTTP requests to potentially evade detection

## Evidence

- Multiple HTTP POST requests to /chkupd.asp containing detailed AV/software configuration
- Use of spoofed or abused domain: us.mcafee.com
- Repeated connections to 216.49.88.118, potentially a C2 server
- Unusual User-Agent: MCUPDATE
- No user-initiated browsing activity — indicative of background automation

## Key Details
- Source IP: 24.6.125.19
- Destination IPs: 208.48.15.13, 209.123.150.14, 216.49.88.118
- User-Agent: MCUPDATE
- HTTP Commands: POST /apps/Agent/en-us/Agent5/chkupd.asp
- Suspicious Parameters: OS=4, IE=6.0.2800.1106, Version=5.0 ,List of .exe and .dll files (indicative of host inventory)
- Port: TCP 80
- Stream Behavior:
  - Multiple connections to same destination over different ports
  - Each conversation includes data exchange (1–4 KB), not just handshakes

## Screenshot
![stream](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/evil1.png)

![pane2](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/evil2.png)

![pane2](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/evil3.png)

![pane2](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/evil4.png)

![pane2](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/evil5.png)

![tcp](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/evil6.png)

## Indicator of Compromise (IOCs)

- IP: 216.49.88.118, 209.123.150.14, 208.48.15.13
- Host Header: us.mcafee.com
- HTTP URI: /apps/Agent/en-us/Agent5/chkupd.asp
- User-Agent: MCUPDATE
- PCAP Timeframe: (based on Rel Start), multiple interactions within seconds

## Conclusion
This PCAP likely captures part of a malware infection lifecycle, specifically the post-exploitation phase where the infected host:
- Profiles its own software environment
- Contacts external servers to exfiltrate data or receive further instructions

## telnet.pcap - Telnet Credentials Disclosure

## Tool
- Wireshark

## Treat Detection
Plaintext Telnet Credentials
Unauthorized remote shell access
Interaction with outdated and potentially vulnerable OpenBSD system

## Evidence 
Username and password sent in cleartext
Full interactive session captured (login, shell commands, file listing, external ping)

## Key Details

- Source IP: 192.168.0.2
- Destination IP: 192.168.0.1
- Username: fake
- Password: user
- Telnet Commands Seen: login, /sbin/ping, ls, ls -a, exit
- Detected Files: .rhosts, .profile, .cshrc, .login, .mailrc
- Port: TCP 23

## Screenshots

![telnet1](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/telnet1.png)

![telnet2](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/telnet2.png)

![telnet3](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/telnet3.png)

## Indicator of Compromise (IOCs)

- Unencrypted Telnet login (no SSL/TLS)
- Credentials (fake/user) visible in raw packet payload
- Interaction with a legacy OpenBSD 2.6-beta host
- .rhosts file presence (suggests rlogin trust configuration)
- External host contacted via ping to www.yahoo.com

## Conclusion 

Telnet communication is entirely unencrypted, exposing both credentials and session activity to passive attackers. Wireshark revealed the full session, including login and command execution. The presence of a .rhosts file suggests risky trust configurations, and the system in question runs a 1999 beta version of OpenBSD, indicating severe potential vulnerabilities.

## email-trouble.pcap - POP3 Email Phishing & Malware Distribution

## Tool 
- Wireshark

## Treat Detection
- Retrieval of malicious emails via POP3
- Executable attachments with suspicious .pif extension
- Potential malware delivery mechanism

## Key Details

Source IP: 161.58.73.170
Destination IP: 12.234.13.202
Protocol: POP3 (TCP port 110)
Suspicious Email Subjects:
    Re: Details
    Re: Approved
Malicious Attachments:
    document_9446.pif
    movie0045.pif
    document_all.pif
Content Indicators:
    Emails contain phrases like “See the attached file for details.”
    Each email includes Content-Type: application/octet-stream and filename=".pif"
RETR Commands Observed:
    RETR 20, RETR 22, RETR 24
    Each retrieving emails with binary file attachments

## Screenshots 

![emaill](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/emailt1.png)

![email](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/emait2.png)

![email](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/emailt3.png)

![email](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/emailt4.png)

Indicator of Compromise (IOCs)

- Executable .pif files disguised as legitimate documents
- Suspicious attachments via POP3
- Emails originating from IP: 12.219.164.63
- Generic and misleading subject lines designed to lure the user

## Conclusion

The email communication captured in email-trouble.pcap indicates malware dissemination through POP3. While no credentials are visible in the capture, multiple emails contain executable attachments using the .pif extension — a known tactic for hiding Windows malware. These emails use social engineering to trick recipients into opening harmful files.

## hackerview.pcap – Telnet Credentials Disclosure and Unauthorized Device Access

## Tool
- Wireshark

## Threat Detection
Cleartext Telnet Credentials Disclosure
Access to Network Infrastructure Device (Matrix N7 Platinum Switch)
Potential Unauthorized Configuration Change Risk

## Key Details
Source IP address:10.100.16.1
Destination IP address :10.100.18.5
Username: admin (entered as aaddmmiinn – each character sent twice due to echo mode)
Password: barrymanilow (note the typo barrymnanilow indicates mistyped input corrected by backspace)
Target Device: Enterasys Networks Matrix N7 Platinum switch

Manufacturer Info:
  - Serial Number: 001188424ee0
  - Firmware Version: 05.35.16

Session Type: Telnet (Unencrypted)
Evidence: Login banner, device prompt Matrix N7 Platinum(su)->, device specifications

## Screenshot

![hacker](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/hacker1.png)

![hacker](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/hacker2.png)

![hacker](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/hacker3.png)

## Indicator of Compromise (IOCs)

- Use of Telnet instead of encrypted protocols (e.g., SSH)
- Credentials visible in plaintext
- Access to critical infrastructure device
- Superuser-level command line prompt (su)

## Conclusion

This Telnet session reveals a major security risk: successful superuser login to a network switch using cleartext credentials. The attacker (192.168.1.103) gained access to the Enterasys Matrix N7 Platinum switch (192.168.1.1), potentially enabling configuration changes or backdoor installations. Telnet should be disabled or blocked, and SSH should be enforced. Logs from the device should be audited for further unauthorized actions.

