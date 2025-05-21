# PCAP-Threat-Analysis-Lab

# ftp.pcap - FTP Credentials Disclosure

## 🔧 Tools Used
- Wireshark
- snort

## 🚨 Threat Detected
- **Plaintext FTP Credentials**
- **Potential unauthorized access**
- **Evidence:** Username and password sent in cleartext, file transfer of `music.mp3`

## 🔎 Key Details
- **Source IP:** 192.168.0.114
- **Destination IP:** 192.168.0.193
- **Username:** `csanders`
- **Password:** `echo`
- **FTP Command:** `USER`, `PASS` seen in cleartext
- **Transferred File:** `music.mp3` (uploaded or downloaded)
- **Port:** TCP 21


## 🖼️ Screenshots

![FTP Credentials in Wireshark](https://github.com/king0fdarkness/PCAP-Threat-Analysis-Lab/blob/main/screenshots/ftp-credentials.png)

Custom Snort Rules (local.rules)

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

🧠 Rule Summary
SID	Description
1000001	Detects USER command
1000002	Detects PASS command
1000003	Detects anonymous login attempts

rules filw : /etc/snort/rules/local.rules

command used :
sudo snort -R /etc/snort/rules/local.rules -r ~/projects/projects/wireshark/credential_exposure/ftp.pcap -A alert_fast -c /etc/snort/snort.lua -l /tmp/

output:

12/16-13:24:40.504807 [**] [1:1000001:1] "FTP USER command detected" [**] [Priority: 0] {TCP} 192.168.0.114:1137 -> 192.168.0.193:21
12/16-13:24:40.507195 [**] [1:1000002:1] "FTP PASS command detected" [**] [Priority: 0] {TCP} 192.168.0.114:1137 -> 192.168.0.193:21

![alert by snort]()

🧩 Indicators of Compromise (IOCs)
Unencrypted FTP login (no SSL/TLS)

Credentials visible in raw packet payload

Anonymous login attempt detected

Insecure transfer of music.mp3

✅ Conclusion
FTP transmits sensitive credentials in plaintext.

Wireshark allowed deep inspection and verification of credential leakage.

Snort was successfully configured to detect both generic and specific FTP login attempts.

To prevent such exposures, use secure alternatives like FTPS or SFTP.
