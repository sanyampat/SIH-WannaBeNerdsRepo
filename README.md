# Secure Data Wiping Tool  

**Team ID:** 86256  
**Team Name:** Wanna Be Nerds  
**Problem Statement:** SIH 25070 – Secure Data Wiping Tool  

---

## 📌 Overview  
Our solution is a **cross-platform secure data wiping tool** designed to ensure **complete and permanent erasure of sensitive data**. It works on **Windows, Linux, and Bootable USB/ISO**, making it effective in both **online and offline environments**.  

The tool supports **HDDs, SATA SSDs, NVMe SSDs, USB drives, and Android devices**, and **automatically applies the most effective sanitization method**. Every wipe is **NIST SP 800-88 compliant** (Clear, Purge, Destroy) and generates a **tamper-proof, digitally signed certificate** as proof of sanitization.  

---

## ✨ Features  
- 🔹 **Cross-platform:** Works on Windows, Linux, and bootable USB/ISO.  
- 🔹 **Multi-device support:** HDD, SSD (SATA/NVMe), USB, and Android.  
- 🔹 **Multiple sanitization methods:**  
  - ATA Secure Erase (SATA HDD/SSD) → Purge  
  - NVMe Format NVM → Purge  
  - Crypto-Erase (SED drives) → Purge/Destroy  
  - Overwrite (zeros/random) → Clear  
- 🔹 **NIST SP 800-88 compliance** (Clear, Purge, Destroy).  
- 🔹 **Verification layer:** Random block checks + device logs.  
- 🔹 **Tamper-proof certificates:** Digitally signed (JSON + PDF).  
- 🔹 **Audit-ready logs:** Timestamped, hashed for security.  
- 🔹 **Safety features:** Dry-run mode, multi-step confirmations, user-friendly interface.  
- 🔹 **Bootable USB support:** Enables offline secure sanitization.  

---

## 🚀 How to Build & Run (Linux)  

### Prerequisites  
- g++ or clang++ (C++17)  
- OpenSSL (`libssl-dev`)  
- Root privileges (`sudo`)  

### Build  
```bash
g++ -std=c++17 sanitize.cpp SanitizeDrives.cpp -o sanitize -lssl -lcrypto
Run (example)
bash
Copy code
# List drives and sanitize (must run as root)
sudo ./sanitize /dev/sdX
⚠️ Important: Do not run on your system disk. Use a test disk or a loopback device.

Safe Test with Loopback Device
bash
Copy code
# Create a 50MB test disk
dd if=/dev/urandom of=test.img bs=1M count=50

# Attach it as a loopback device
sudo losetup /dev/loop10 test.img

# Run sanitizer
sudo ./sanitize /dev/loop10

# Verify (should be zeroed)
hexdump -C /dev/loop10 | head

# Detach
sudo losetup -d /dev/loop10
📜 Certificate Example (JSON)
json
Copy code
{
  "certificate_id": "wiper-20250924-0001",
  "device": {
    "model": "Samsung SSD",
    "type": "NVMe"
  },
  "wipe": {
    "method": "NVMe Format NVM",
    "nist_level": "Purge",
    "start_time": "2025-09-24T14:12:03Z",
    "end_time": "2025-09-24T14:12:21Z"
  },
  "verification": {
    "samples_read": 16,
    "result": "passed"
  },
  "signature": "MEUCIQ..."
}
🛡️ Security & Compliance
NIST SP 800-88 compliant (Clear, Purge, Destroy).

Digital certificates prove sanitization.

Public key verification prevents forgery.

Logs are hashed and tamper-proof.

👨‍💻 Team Members
Wanna Be Nerds (Team ID: 86256)

⚠️ Disclaimer
This tool is designed for secure data wiping. Running it on active system disks will result in permanent data loss. Use with caution.
