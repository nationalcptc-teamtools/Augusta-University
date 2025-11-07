# 🕸️ NetWeaver

**NetWeaver** is a lightweight **network visualization and enumeration tool** built for penetration testing and red team operations.
It automates scanning a target or subnet with `nmap`, parses the XML results, and renders an **interactive HTML map** that looks and feels similar to **BloodHound** — but for network services.

---

## 📋 Features

* **One-command recon → visualization**

  * Runs a full TCP service discovery scan using Nmap (`-Pn -sS -sV -p- -T4`).
  * Parses the XML results directly — no third-party libraries or dependencies.
  * Generates a single self-contained `HTML` file you can open in any browser.

* **Hierarchical (pyramid) layout**

  * Subnets at the top
  * Hosts under their subnet
  * Ports and services fanning out beneath each host

* **Interactive & draggable**

  * Drag subnet, host, or port nodes freely.
  * Click any node for details (IP, OS, service, version info).
  * Lines never block clicks (pointer-safe visualization).

* **Portable**

  * Generates a single HTML file — no external JS, CSS, or images.
  * Works completely offline (ideal for isolated CTF/CPTC or lab networks).

---

## ⚙️ Installation

### Prerequisites

* **Python 3.8+**
* **Nmap** 

### Clone

```bash
git clone https://github.com/nationalcptc-teamtools/Augusta-University.git
cd NetWeaver
```

---

## 🚀 Usage

### 1. Run a new scan and visualize

```bash
python3 NetWeaver.py <IP>/<CIDR> <HTML file name (Optional)>
```

* Runs Nmap across the subnet.
* Generates an HTML file like this unless specified in command:

  ```
  netweaver_1728354842.html
  ```
* Open that file in a browser to explore the network graph.

## 🧩 Example Output

When opened, you’ll see:

* **Subnets** as teal nodes at the top.
* **Hosts** below them, in blue.
* **Ports/services** in orange nodes below each host.
* Click or drag any node:

  * **Subnet node:** lists hosts and open port counts.
  * **Host node:** lists OS, vendor, and all discovered services.
  * **Port node:** shows protocol, product, and version info.

---

## 🧠 How It Works

1. **Scan Stage:**
   `nmap -Pn -sS -sV -p- -T4 -oX scan.xml <target>`
2. **Parse Stage:**
   Python extracts IPs, OS fingerprints, ports, and services.
3. **Render Stage:**
   Generates an interactive SVG-based graph (no dependencies).

---

## 🧰 Recommended Setup

Add a helper alias to your `.bashrc`:

```bash
alias netweaver='python3 ~/tools/NetWeaver/NetWeaver.py'
```

Then you can run:

```bash
netweaver 10.0.2.0/24 netResults.html
```