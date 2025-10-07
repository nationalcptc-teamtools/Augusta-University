# 🛡️ Competition Scenario Playbook

This document outlines the planned response and resources for key scenarios encountered during the competition assessment phase.

---

## 🧠 Situation 1: Large Language Model (LLM) Assessment

In the case that we encounter a Large Language Model on the DMZ, two members of the CPTC team will be designated as **Prompt Engineers**.

- They will focus on **LLM Evasion and Injection Testing** to identify potential weaknesses that could reveal information to aid in testing a host outside the DMZ.

### 📚 Resources
- [PortSwigger: LLM Attacks](https://portswigger.net/web-security/llm-attacks)
- [Snyk: Addressing Risks in the OWASP Top 10 for LLMs](https://snyk.io/blog/addressing-risks-in-the-owasp-top-10-for-llms/)

---

## 📧 Situation 2: Social Engineering Testing

In the case where we can perform a simulated social engineering test, the Head of Phishing and Emails will lead the planning and execution of this campaign.

- **Goal:** Safely test the client's human defense layer and measure susceptibility to **phishing or credential harvesting**, focusing on defensive reporting.

### 📚 Resources
- [GitHub: Social-Engineer Toolkit (SET)](https://github.com/trustedsec/social-engineer-toolkit)
- [Cyberly: How do you use SET to perform a spear phishing attack?](https://www.cyberly.org/en/how-do-you-use-set-to-perform-a-spear-phishing-attack/index.html)

---

## ☁️ Situation 3: Cloud Platform Assessment

In the event that we find the cloud platform that the client is using for their infrastructure, two members will be tasked with **discovering and testing the security configuration of cloud resources** running on the infrastructure.

### 📚 Resources
- [GitHub: S3Scanner (for S3 bucket discovery)](https://github.com/sa7mon/S3Scanner)
- [GitHub: GCPGoat Attack Manuals (Module 1)](https://github.com/ine-labs/GCPGoat/tree/main/attack-manuals/module-1)
- [GitHub: AzureGoat Attack Manuals (Module 1)](https://github.com/ine-labs/AzureGoat/tree/master/attack-manuals/module-1)
- [GitHub: AWSGoat Attack Manuals (Module 1)](https://github.com/ine-labs/AWSGoat/tree/master/attack-manuals/module-1)

---

## 🌐 Situation 4: Web Application Testing

In the situation where we are faced with a web application and need to find a way to assess the network perimeter, team members will **test for and document web vulnerabilities** that could demonstrate a potential entry point.

### 📚 Resources
- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
- [PortSwigger: Web Security All Materials](https://portswigger.net/web-security/all-materials)
- [PHP Manual: MySQL Functions](https://www.php.net/manual/en/book.mysql.php)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [W3Schools: PHP Tutorial](https://www.w3schools.com/php/default.asp)
