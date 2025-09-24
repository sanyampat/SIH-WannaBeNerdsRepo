#include <iostream>
#include <string>

struct DriveInfo {
    std::string name;   // e.g., "C:" or "/dev/sda"
    std::string type;   // HDD, SATA SSD, NVMe SSD, USB, etc.
    std::string bus;    // sata, nvme, usb, etc.
    bool isSED = false; // self-encrypting drive?
};

void ataSecureErase(const DriveInfo& d) {
    std::cout << "[*] ATA Secure Erase -> " << d.name << "\n";
    // TODO: implement ATA secure erase (IOCTL/hdparm)
}
void cryptoGraphicErase(const DriveInfo& d) {
    std::cout << "[*] Crypto Erase -> " << d.name << "\n";
    // TODO: implement crypto erase
}
void nvmeFormatNVM(const DriveInfo& d) {
    std::cout << "[*] NVMe Format NVM -> " << d.name << "\n";
    // TODO: implement NVMe format
}

// --- Decision Function ---
void sanitizeDrive(const DriveInfo& d) {
    if (d.isSED) {
        cryptoGraphicErase(d);
    } else if (d.bus == "sata" && (d.type == "HDD" || d.type == "SATA SSD")) {
        ataSecureErase(d);
    } else if (d.bus == "nvme") {
        nvmeFormatNVM(d);
    } else if (d.bus == "usb") {
        singlePass(d);
        std::cout << "   [!] Warning: USB/SD overwrite = CLEAR, not PURGE. "
                  << "Recommend destruction for sensitive data.\n";
    } else {
        singlePass(d);
        std::cout << "   [!] Unknown bus type, using overwrite fallback.\n";
    }
}

int main() {
#ifdef _WIN32
    std::cout << "Windows (32-bit or 64-bit)" << std::endl;
#elif __linux__
    std::cout << "Linux" << std::endl;
#else
    std::cout << "Unknown OS" << std::endl;
#endif

    // Example drives (in practice, populate via your getDrives())
    DriveInfo d1{"C:", "HDD", "sata", false};
    DriveInfo d2{"D:", "NVMe SSD", "nvme", false};
    DriveInfo d3{"E:", "SATA SSD", "sata", true}; // SED
    DriveInfo d4{"F:", "USB Storage", "usb", false};

    sanitizeDrive(d1);
    sanitizeDrive(d2);
    sanitizeDrive(d3);
    sanitizeDrive(d4);

    return 0;
}
