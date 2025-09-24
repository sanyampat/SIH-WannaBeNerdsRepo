// sih_wipe_auto_detect.cpp
// Cross-platform: detects HDD / SATA-SSD / NVMe and calls appropriate wiper.
// Compile: Linux: g++ -O2 -std=c++17 sih_wipe_auto_detect.cpp -o sih_wipe
//          Windows: compile with Visual Studio (Windows SDK required)

#include <iostream>
#include <string>
#include <memory>
#include <cstdlib>
#include <vector>

#ifdef __linux__
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <initguid.h>
#endif

// Abstract base
class DataWiper {
public:
    virtual bool erase(const std::string &device, const std::string &type) = 0;
    virtual ~DataWiper() = default;
};

// Linux implementation (high-level orchestration)
#ifdef __linux__
class LinuxWiper : public DataWiper {
public:
    bool erase(const std::string &device, const std::string &type) override {
        std::cout << "[LinuxWiper] device=" << device << " type=" << type << "\n";
        if (type == "HDD") {
            // Overwrite with shred (example). Replace with your overwrite routine if preferred.
            std::string cmd = "shred -vzn 3 " + device;
            return system(cmd.c_str()) == 0;
        } else if (type == "SATA-SSD") {
            // Try ATA secure erase (hdparm). Requires hdparm installed and root.
            std::string setpass = "hdparm --user-master u --security-set-pass P " + device;
            std::string erase = "hdparm --user-master u --security-erase P " + device;
            std::cout << "[LinuxWiper] running: " << setpass << "\n";
            if (system(setpass.c_str()) != 0) {
                std::cerr << "[LinuxWiper] security-set-pass failed; falling back to overwrite\n";
                return system(("shred -vzn 3 " + device).c_str()) == 0;
            }
            std::cout << "[LinuxWiper] running: " << erase << "\n";
            return system(erase.c_str()) == 0;
        } else if (type == "NVMe") {
            // Use nvme-cli format with SES=1 (crypto erase) if available.
            std::string cmd = "nvme format " + device + " --ses=1 --force";
            std::cout << "[LinuxWiper] running: " << cmd << "\n";
            int r = system(cmd.c_str());
            if (r == 0) return true;
            // fallback: try ses=2
            cmd = "nvme format " + device + " --ses=2 --force";
            return system(cmd.c_str()) == 0;
        } else {
            std::cerr << "[LinuxWiper] Unknown type: " << type << "\n";
            return false;
        }
    }
};
#endif

// Windows implementation (high-level orchestration)
#ifdef _WIN32
class WindowsWiper : public DataWiper {
public:
    bool erase(const std::string &device, const std::string &type) override {
        std::cout << "[WindowsWiper] device=" << device << " type=" << type << "\n";
        if (type == "HDD") {
            // Use cipher /w for wiping free space. For full disk overwrite, use raw write routine.
            // Here we call cipher as a simple demonstration.
            std::string cmd = "cipher /w:";
            // device might be "C:" or a mount point. If user passed raw physical path, implement WriteFile loop.
            if (device.size() > 1 && device[1] == ':') {
                cmd += device;
            } else {
                // If given \\.\PhysicalDriveN, we should implement raw overwrite via CreateFile + WriteFile.
                // Placeholder fallback:
                std::cerr << "[WindowsWiper] raw physical overwrite not implemented in demo. Use admin tool.\n";
                return false;
            }
            return system(cmd.c_str()) == 0;
        } else if (type == "SATA-SSD" || type == "NVMe") {
            // Attempt to run vendor tools or call native DeviceIoControl-based routines.
            // For SIH prototype we recommend booting to Linux for AV-guaranteed secure erase.
            std::cerr << "[WindowsWiper] SSD secure erase on Windows is vendor/driver dependent.\n";
            std::cerr << "You can call vendor CLI tools (e.g., Samsung/Intel) or implement DeviceIoControl NVMe/ATA IOCTLs.\n";
            return false;
        } else {
            std::cerr << "[WindowsWiper] Unknown type: " << type << "\n";
            return false;
        }
    }
};
#endif

// Factory
std::unique_ptr<DataWiper> getWiper() {
#ifdef _WIN32
    return std::make_unique<WindowsWiper>();
#elif defined(__linux__)
    return std::make_unique<LinuxWiper>();
#else
    return nullptr;
#endif
}

// Device-type detection: returns one of {"HDD", "SATA-SSD", "NVMe", "UNKNOWN"}

// Linux detection
#ifdef __linux__
static std::string linux_detect_type(const std::string &devpath) {
    // devpath like "/dev/sda" or "/dev/nvme0n1"
    std::string base = devpath.substr(devpath.find_last_of('/') + 1);

    // Quick NVMe name check: nvme* typically NVMe devices
    if (base.rfind("nvme", 0) == 0) {
        return "NVMe";
    }
    // Check rotational flag
    std::string sysrot = "/sys/block/" + base + "/queue/rotational";
    std::ifstream ifs(sysrot);
    if (ifs.is_open()) {
        int val = 1;
        ifs >> val;
        ifs.close();
        if (val == 0) return "SATA-SSD"; // non-rotational -> SSD
        else return "HDD";
    }

    // Fallback: parse /sys/block/<base>/device/model or /sys/block/<base>/device/* for clues
    std::string modelPath = "/sys/block/" + base + "/device/model";
    std::ifstream mfs(modelPath);
    if (mfs.is_open()) {
        std::string model;
        std::getline(mfs, model);
        mfs.close();
        std::transform(model.begin(), model.end(), model.begin(), ::tolower);
        if (model.find("ssd") != std::string::npos || model.find("nvme") != std::string::npos)
            return (model.find("nvme") != std::string::npos) ? "NVMe" : "SATA-SSD";
    }
    return "UNKNOWN";
}
#endif

// Windows detection using IOCTL_STORAGE_QUERY_PROPERTY
#ifdef _WIN32
static std::string windows_detect_type(const std::string &device) {
    // Accepts drive letter "C:" or physical path like "\\\\.\\PhysicalDrive0"
    std::string path = device;
    if (device.size() == 2 && device[1] == ':') {
        // convert to volume path \\.\C:
        path = std::string("\\\\.\\") + device;
    }
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        std::cerr << "[windows_detect_type] CreateFile failed: " << GetLastError() << "\n";
        return "UNKNOWN";
    }

    // Query device property
    STORAGE_PROPERTY_QUERY query;
    ZeroMemory(&query, sizeof(query));
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;

    BYTE outBuffer[1024];
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
                              &query, sizeof(query),
                              &outBuffer, sizeof(outBuffer),
                              &bytes, NULL);
    if (!ok) {
        std::cerr << "[windows_detect_type] DeviceIoControl failed: " << GetLastError() << "\n";
        CloseHandle(h);
        return "UNKNOWN";
    }

    STORAGE_DEVICE_DESCRIPTOR* desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(outBuffer);
    // desc->BusType gives the bus type (BusTypeNvme, BusTypeAta, etc.)
    switch (desc->BusType) {
        case BusTypeNvme:
            CloseHandle(h); return "NVMe";
        case BusTypeAta:
        case BusTypeSata:
            // need to differentiate HDD vs SSD: use rotational property via MEDIA_TYPE? Not reliable.
            // Query for rotational info via STORAGE_DEVICE_MEDIA_INFO_EX or use WMI (complex).
            // For prototype, assume ATA -> check model string for "ssd"
        {
            // Try to read Vendor/Model & check for 'ssd'
            std::string model;
            if (desc->ProductIdOffset && desc->ProductIdOffset < bytes) {
                char *p = (char*)outBuffer + desc->ProductIdOffset;
                model = std::string(p);
                std::transform(model.begin(), model.end(), model.begin(), ::tolower);
                if (model.find("ssd") != std::string::npos) {
                    CloseHandle(h); return "SATA-SSD";
                }
            }
            CloseHandle(h);
            return "HDD";
        }
        default:
            CloseHandle(h);
            return "UNKNOWN";
    }
}
#endif

// Public wrapper
std::string detect_device_type(const std::string &device) {
#ifdef __linux__
    return linux_detect_type(device);
#elif _WIN32
    return windows_detect_type(device);
#else
    return "UNKNOWN";
#endif
}

// Helper: prompt confirmation
bool confirm_device(const std::string &device) {
    std::cout << "You are about to wipe device: " << device << "\n";
    std::cout << "Type the device basename to confirm (e.g., sda or C:): ";
    std::string in;
    std::cin >> in;
    std::string base = device.substr(device.find_last_of('/') + 1);
#ifdef _WIN32
    if (device.size() == 2 && device[1] == ':') base = device;
#endif
    return in == base;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: sudo " << argv[0] << " <device_path>\n";
        std::cerr << " Example Linux: /dev/sda  or /dev/nvme0n1\n";
        std::cerr << " Example Windows: C:  or \\\\.\\PhysicalDrive0\n";
        return 1;
    }

    std::string device = argv[1];
    auto wiper = getWiper();
    if (!wiper) {
        std::cerr << "Unsupported OS or build.\n";
        return 1;
    }

    std::string type = detect_device_type(device);
    std::cout << "Detected type: " << type << "\n";

    if (!confirm_device(device)) {
        std::cerr << "Confirmation mismatch — aborting.\n";
        return 1;
    }

    bool ok = wiper->erase(device, type);
    std::cout << "Erase returned: " << (ok ? "success" : "failure") << "\n";

    // Here: generate signed certificate, logs etc. (call your previous routines)
    // e.g., generateCertificate(device, type, ok);

    return ok ? 0 : 2;
}
