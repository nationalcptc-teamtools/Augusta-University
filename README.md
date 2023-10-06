# Security Tools Overview

This repository provides an overview of various security tools categorized into Reconnaissance and Enumeration, Initial Access, and Privilege Escalation. Each tool serves specific purposes in the field of cybersecurity.

## Reconnaissance and Enumeration

### Rustscan
- A fast, efficient, and reliable port scanner written in Rust.
  - Basic Syntax: `rustscan <target>`

### DNSRecon
- A powerful DNS enumeration tool that helps discover DNS information about a target.
  - Basic Syntax: `dnsrecon -d <target_domain>`

### SSLyze
- A fast and comprehensive SSL/TLS analysis tool to identify vulnerabilities in SSL/TLS configurations.
  - Basic Syntax: `sslyze --regular <target_host>`

### The Harvester
- A tool for gathering email accounts, subdomains, hosts, employee names, open ports, and banners from different public sources.
  - Basic Syntax: `theharvester -d <target_domain> -l <results_limit>`

### Recon-NG
- An advanced open-source tool for web reconnaissance that gathers information from various sources.
  - Basic Syntax: `recon-ng`
 
### Enumerating-ICS-SCADA-Devices
A compilation of scripts and scans for discovering and enumerating industrial control and SCADA devices. Utilizing open-source tools, I have compiled scans and scripts for targeting Operational Technology (OT) devices and hosts! 

## Initial Access

### ExploitDB
- A comprehensive archive of publicly known exploits and corresponding vulnerable software.
  - Basic Syntax: `searchsploit <search_query>`

### Trickest
- A tool that helps identify the most tricky and elusive phishing domains.
  - Basic Syntax: `trickest <target_url>`

### CVE Search
- A tool to search for Common Vulnerabilities and Exposures (CVE) information to understand vulnerabilities in specific software.
  - Basic Syntax: `cve-search <cve_id>`

## Privilege Escalation

### Peas
- A Privilege Escalation Awesome Scripts Suite, designed to automate the identification and exploitation of privilege escalation vulnerabilities.
  - Basic Syntax: `peas`

## Exfiltration Tools (Writing Tools)

### TCM Security Template
- A template for documenting and organizing security-related information.

### PWNDoc
- A documentation generator for penetration testers and bug bounty hunters to automate the reporting process.

### Envision/PCF
- Tools for envisioning, planning, and executing penetration testing engagements.

## Contributing
Feel free to contribute by adding more tools, improving the documentation, or suggesting new categories and subcategories for a better organization.

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠴⠞⠛⣧⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡤⡶⠟⢁⠴⣾⠀⡏⠀⠀⠀⠀⠀⠀⠉⠉⠙⠲⠤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢠⡤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡤⠒⠉⡡⠊⣠⠞⠁⠀⡏⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠓⠦⣀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠸⣇⠀⠉⠑⠒⠤⠤⣀⡀⣠⠖⠁⠀⢀⠞⢀⡔⠁⠀⠀⠀⡇⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠑⢄⠀⠀⠀⠀
⠀⠀⠀⠀⢻⡀⠀⠀⠀⠀⠀⢠⠟⠁⠀⠀⠀⠃⠀⠈⠉⠒⠶⢤⣀⣧⠀⢧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢆⠀⠀
⠀⠀⠀⠀⠀⢣⡀⠀⠀⠀⡴⠁⠀⠀⠀⠀⢀⡠⠒⠒⠒⠒⠲⣄⠈⠉⠀⠺⠆⠀⠀⠀⠀⠀⠀⠒⠢⢤⣀⠀⠀⣀⣀⣀⣀⣀⠀⠀⠱⡄
⠀⠀⠀⠀⠀⠀⢙⡶⠲⢾⡀⠀⠀⠀⠀⣠⠎⢀⡠⠤⠤⠤⣄⠈⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠯⡀⠀⠀⠀⠈⠉⠛⠓⠾
⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⠋⠀⠀⠀⠀⠈⢧⢸⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢢⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠸⣶⣶⠀⠀⠀⠀⠀⠀⣼⠁⠀⠀⣠⡀⠀⠀⢸⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣆⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠹⣯⣇⠀⠀⠀⠀⢠⠇⠀⠀⢸⣇⣹⠀⠀⢸⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣆⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢻⠙⡆⡆⠀⠀⢸⠀⠀⠀⠘⣷⣧⡇⢀⣯⣤⣄⠀⠀⠀⠀⣠⠚⠉⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡄⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⢧⢹⣧⣀⢀⡞⠀⠀⠀⠀⠹⣝⡿⢫⡤⣀⠈⢳⠀⡠⠞⠁⠀⣰⠇⠀⠈⠙⠲⣄⠀⠀⠀⠀⠀⠀⠀⢷⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢠⣤⣬⣷⢿⣿⡿⠦⠤⠤⠤⠤⠶⠋⣠⠞⣸⣿⣀⠿⠊⠀⠀⣠⠞⠁⠀⠀⠀⠀⠀⠈⢷⣄⠀⠀⠀⠀⠀⢸⡆⠀⠀
⠀⠀⠀⠀⠀⣠⠤⠚⠻⠿⣿⡿⢿⣇⡀⠀⠀⠀⠀⣰⡮⠟⠛⠉⠋⠀⠲⢤⣶⡋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣦⠙⢦⡀⠀⠀⢸⡇⠀⠀
⠀⠀⠀⢀⡞⠁⠀⠀⠀⠀⢀⠿⠿⢽⣻⡭⠶⡶⠊⠁⠀⠀⠀⠀⠀⠀⣀⠀⠈⡏⠲⢤⡀⠀⠀⠀⠀⠀⠀⠀⠸⡄⠀⠘⢦⡀⢸⡇⠀⠀
⠀⠀⠀⢸⠀⠀⠀⠀⠀⣰⠃⣀⣠⣼⠋⠀⢸⠁⠀⠀⠀⠀⠀⠀⠠⡄⠀⢳⣀⡿⢦⡀⠈⢦⡀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⢳⣸⠇⠀⠀
⠀⠀⠀⢸⡀⠀⣀⣀⡴⣏⠉⠁⠀⢧⠀⡀⠸⡄⠀⠀⠀⠀⣠⡤⠀⠘⡆⣸⢿⡀⠀⠹⡄⠀⠹⡄⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠛⠀⠀⠀
⠀⠀⠀⠀⠻⢤⣈⣉⣇⣈⣹⡋⠓⠛⢦⣹⣄⣙⣲⠶⠖⢲⡏⡀⢀⡼⠋⠁⠈⡟⢄⡼⠇⠀⠀⠹⡀⠀⠀⠀⣰⠃⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢄⠀⠀⠀⠀⡟⠀⠀⠀⢸⡿⠿⢅⡀⠀⠀⠀⢹⠀⠀⠀⠀⠀⠀⣇⠀⠀⢠⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢦⣤⣴⠁⠀⠀⠀⡏⠱⡀⠀⠈⠢⡀⠀⢸⠀⠀⠀⠀⠀⠀⢸⠀⢀⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣆⠉⢲⢦⡀⠀⢻⡄⠙⢄⡀⠀⠹⣆⡜⠀⠀⠀⠀⠀⠀⢸⣧⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⡄⠘⡆⢳⠀⠈⢿⠲⢄⡙⢦⡀⠸⠃⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢣⠀⢻⠈⡆⠀⠘⡆⠀⠈⠉⠉⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡀⠘⡇⢹⠀⠀⢻⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⢹⠈⡇⠀⠈⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡤⢶⣶⣷⠀⠈⣷⣿⡄⠀⢹⣦⠤⢄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣇⠀⠉⠉⢛⡿⣛⠽⢇⠀⠀⣿⡽⠛⢹⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⡀⠉⠁⠀⢾⠀⠙⠓⠛⠉⠉⠁⠀⣠⠞⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣀⣤⠖⠊⠉⠀⠉⠻⡖⠲⠤⢬⠗⠲⠦⠤⠀⠀⠀⠈⠁⠀⣸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣀⠴⠊⠁⠈⠓⣄⠀⠀⠀⠀⠈⢦⠀⠘⣧⡀⠀⠀⠀⠀⣀⣀⢤⣞⡥⠽⠦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢀⡴⠊⠁⠀⠀⠀⠀⠀⠈⡆⠀⠀⠀⠀⠘⡆⢠⡇⠈⠉⠉⠉⢉⡵⠊⠁⠀⠀⠀⠀⠈⠻⣝⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣠⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀⢱⠀⠀⠀⠀⠀⡇⢸⡇⠀⠀⠀⣠⠋⠀⠀⠀⠀⠀⠀⢀⣀⠤⠬⠧⡳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠻⢿⣖⣒⣶⣶⣶⣶⣶⣶⣦⣼⣶⣶⣶⣶⣶⣿⣾⣇⠀⠀⢠⠇⠀⠀⠀⠀⠀⢀⠔⠁⠀⠀⠀⠀⠙⣟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠈⠉⠉⠙⠳⣕⢦⣼⠀⠀⠀⠀⠀⢠⠃⠀⠀⠀⠀⠀⠀⠀⠘⢧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⢯⣓⠤⣄⡀⠀⡼⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠲⢯⣝⡳⠤⣄⣀⠀⠀⠀⠀⠀⠀⠀⢸⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⡙⠓⠒⠿⠭⠷⣶⣶⣲⣶⢿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀
