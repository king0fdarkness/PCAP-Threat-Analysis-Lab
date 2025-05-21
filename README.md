# PCAP-Threat-Analysis-Lab

# ftp.pcap - FTP Credentials Disclosure

## 🔧 Tools Used
- Wireshark

## 🚨 Threat Detected
- **Plaintext FTP Credentials**
- **Potential unauthorized access**

## 🔎 Key Details
- **Source IP:** 192.168.0.114
- **Destination IP:** 192.168.0.193
- **Username:** `csanders`
- **Password:** `echo`
- **FTP Command:** `USER`, `PASS` seen in cleartext
- **Transferred File:** `music.mp3` (uploaded or downloaded)
- **Port:** TCP 21

## 🧩 Indicators of Compromise
- Unencrypted credentials
- No SSL/TLS protection
- Possible unauthorized access to FTP server
- - FTP authentication performed without encryption
- Credentials visible directly in packet payload
- Unprotected file transfer of `music.mp3`

## ✅ Conclusion
The use of plain FTP protocol exposes user credentials to interception. Secure protocols like FTPS or SFTP are recommended to prevent MITM attacks.

## 🖼️ Screenshots

![FTP Credentials in Wireshark](../screenshots/ftp-credentials.png)
