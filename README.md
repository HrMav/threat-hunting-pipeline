# 🛡️ Enterprise Threat Hunting Pipeline
### Detection, Isolation, and SIEM Analysis in a Segmented Home Lab

![Status](https://img.shields.io/badge/Status-Operational-brightgreen) ![Focus](https://img.shields.io/badge/Focus-Blue%20Team%20%7C%20SOC%20Architecture-blue)

## 📖 Overview
This project demonstrates a fully functional **Security Operations Center (SOC)** architecture designed to capture, isolate, and analyze real-world cyber threats. 

Unlike a standard install, this environment isolates "live" malware in a secure **DMZ** while tunneling threat intelligence into a protected **LAN** for analysis. It processes **14,000+ daily attack events**, correlating network intrusion data (NIDS) with endpoint telemetry (EDR).

## 🏗️ Architecture & Network Flow

**The Flow of an Attack:**
1.  **Ingress:** Attacker targets Public IP $\rightarrow$ Hits **OPNsense Firewall**.
2.  **Isolation:** OPNsense routes traffic to a **VLAN 66 (DMZ)**, strictly blocked from accessing the internal LAN.
3.  **Deception:** Traffic reaches **T-Pot Honeypot**, where services like *Cowrie* (SSH) and *Suricata* (Network) capture the payload.
4.  **Ingestion:** A custom-configured **Wazuh Agent** reads the raw JSON logs from the Honeypot's Docker volumes.
5.  **Analysis:** Logs are tunneled through a strict firewall pinhole (Port 1515/1514) to the **Wazuh Manager** in the secure LAN.

## 🛠️ Tech Stack

| Component | Technology | Role |
| :--- | :--- | :--- |
| **Firewall / Router** | OPNsense | VLAN Segmentation, NAT, ACL Rules. |
| **SIEM / XDR** | Wazuh | Log Correlation, FIM, Alerting. |
| **Honeypot Platform** | T-Pot (Debian) | Threat Data Collection (Suricata, Cowrie, Nginx). |
| **Virtualization** | Proxmox VE | Hosting Infrastructure (LXC / VMs). |
| **Containerization** | Docker | Microservices for Honeypot sensors. |

## 📸 Project Gallery

### 1. The Evidence: Live Threat Ingestion
*Wazuh SIEM dashboard visualizing live SSH brute force and Suricata network alerts tunneled from the DMZ.*
![Wazuh Dashboard] <img width="1864" height="950" alt="tpotwazuh" src="https://github.com/user-attachments/assets/2355555b-f3f5-4aef-9465-c4502a4ae346" />

### 2. The Trap: Global Attack Map
*Real-time visualization of 14,000+ daily attacks against the Honeypot sensors.*
![T-Pot Attack Map] <img width="1864" height="950" alt="tpot" src="https://github.com/user-attachments/assets/ec409364-8da2-4dc2-992b-c4b8dc0ef840" />

<img width="1864" height="950" alt="Screenshot from 2025-12-22 11-55-58" src="https://github.com/user-attachments/assets/216fe747-a4c3-488a-bc38-03f2da9b65fc" />

<img width="1864" height="950" alt="Screenshot from 2025-12-22 11-56-13" src="https://github.com/user-attachments/assets/caea3e72-50e4-4f37-86ff-652c2f689ef8" />

### 3. The Shield: Network Segmentation
*OPNsense firewall rules enforcing a "Default Deny" policy between the DMZ and critical internal assets.*
![Firewall Rules] <img width="1864" height="950" alt="opnsense" src="https://github.com/user-attachments/assets/0812191d-3373-419c-98bc-2aef9d4ca957" />

## 🔧 Engineering Challenges & Solutions

### Challenge 1: The "Blind Agent" Problem
**Issue:** The Wazuh Agent runs as a restricted user and could not read T-Pot's Docker logs (`eve.json`), which are owned by root.
**Solution:** Implemented **Access Control Lists (ACLs)** to grant granular read-access to the agent without elevating privileges to root.

bash
sudo setfacl -R -m u:wazuh:rx /home/cipher/tpotce/data

### Challenge 2: Double-NAT & Docker Routing
**Issue:** T-Pot's internal Docker bridges (`172.x`) conflicted with the OPNsense routing table, causing packet loss when the agent tried to report to the SIEM.
**Solution:** Configured persistent static routing on the Debian host to prioritize the OPNsense gateway for LAN traffic.
bash
ip route add 192.168.x.x/24 via 192.168.x.x dev ens18

### Challenge 3: Secure Log Tunneling
**Issue:** How to get logs *out* of a locked-down DMZ without opening the LAN to hackers?
**Solution:** Created a strict **Firewall Alias** (`WAZUH_SERVER`) and a "Pinhole Rule" in OPNsense allowing traffic **only** on TCP ports 1514/1515 from the Honeypot IP to the SIEM IP.

## 🚀 Key Capabilities Demonstrated
* **Network Security:** VLAN segmentation, Firewall Rule creation, NAT traversal.
* **Log Management:** JSON log parsing, custom `ossec.conf` ingestion rules.
* **Threat Intelligence:** Differentiating between "Internet Noise" (AppArmor false positives) and "Targeted Attacks" (SSH Brute Force).
* **Linux Administration:** File permissions (ACLs), Service management (Systemd), Network debugging (`netcat`, `tcpdump`).
