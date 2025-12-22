# 🛠️ Technical Configuration Guide

This document details the specific configurations required to integrate T-Pot (Honeypot) with Wazuh (SIEM) through an OPNsense Firewall.

## 1. OPNsense Firewall Configuration
To allow the DMZ Honeypot to send logs to the LAN SIEM without exposing the internal network.

### A. Create an Alias
* **Name:** `WAZUH_SERVER`
* **Type:** Host(s)
* **Content:** `<WAZUH_MANAGER_IP>` (e.g., 192.168.x.x)

### B. Create a DMZ Rule
Navigate to **Firewall > Rules > Honeypot_DMZ** and add:
* **Action:** Pass
* **Protocol:** TCP
* **Source:** DMZ Net (or specific T-Pot IP)
* **Destination:** `WAZUH_SERVER`
* **Port Range:** `1514` to `1515`
* **Description:** "Allow Wazuh Agent Reporting"

---

## 2. T-Pot (Debian) Network Fix
Docker containers on T-Pot utilize internal bridge ranges (e.g., `172.16.x.x`) which can conflict with the physical gateway routing.

**Fix: Add a persistent static route to the OPNsense Gateway.**

bash
Verify the current route
ip route show

Add the route manually
Replace <LAN_NETWORK_CIDR> with your internal network (e.g., 192.168.1.0/24)
Replace <GATEWAY_IP> with your firewall's interface IP
sudo ip route add <LAN_NETWORK_CIDR> via <GATEWAY_IP> dev ens18

## 3. Wazuh Agent Configuration (The "Spy")
### A. Installation on T-Pot

Import the GPG Key
curl -s [https://packages.wazuh.com/key/GPG-KEY-WAZUH](https://packages.wazuh.com/key/GPG-KEY-WAZUH) | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg

Add Repo
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] [https://packages.wazuh.com/4.x/apt/](https://packages.wazuh.com/4.x/apt/) stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list

Install Agent pointing to Manager
Replace <WAZUH_MANAGER_IP> with the actual IP address
sudo apt-get update
sudo WAZUH_MANAGER="<WAZUH_MANAGER_IP>" apt-get install wazuh-agent

### B. Ingesting Honeypot Logs

Edit the configuration file: /var/ossec/etc/ossec.conf

Add the following block inside the <ossec_config> tags to read the raw JSON attack data. Note: Ensure the paths match your T-Pot installation (replace <USER> with your actual username).

<localfile>
    <log_format>json</log_format>
    <location>/home/<USER>/tpotce/data/suricata/log/eve.json</location>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/home/<USER>/tpotce/data/cowrie/log/cowrie.json</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/home/<USER>/tpotce/data/nginx/log/access.log</location>
  </localfile>

### C. Solving Permission Issues (ACLs)

The Wazuh agent runs as user wazuh and cannot read T-Pot logs by default. Use Access Control Lists (ACLs) to grant specific read-access without modifying root ownership.

Install ACL tools
sudo apt-get install acl

Recursively grant read/execute access to the data folder
Replace <USER> with your actual username
sudo setfacl -R -m u:wazuh:rx /home/<USER>/tpotce/data

### D. Restart Service
sudo systemctl restart wazuh-agent
