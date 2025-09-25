// SanitizeDrives.cpp
// Cross-platform drive detection + sanitization
// WARNING: This code performs destructive operations. Use only on test systems.

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <sstream>
#include "sanitize.h"

// --- platform-specific getDrives implementations (Windows/Linux) ---
// (kept same as your pasted version; added USB dismount call in sanitizeDrive)

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#include <vector>

static std::string trimTrailingBackslash(const std::string& s) {
    if (!s.empty() && (s.back() == '\\' || s.back() == '/'))
        return s.substr(0, s.size() - 1);
    return s;
}

std::vector<DriveInfo> getDrives() {
    std::vector<DriveInfo> drives;

    DWORD driveMask = GetLogicalDrives();
    for (char c = 'A'; c <= 'Z'; ++c) {
        if (!(driveMask & (1 << (c - 'A')))) continue;

        std::string root = std::string(1, c) + ":\\"; // "C:\"
        UINT driveType = GetDriveType(root.c_str());
        if (driveType != DRIVE_FIXED && driveType != DRIVE_REMOVABLE)
            continue;

        DriveInfo info;
        info.name = std::string(1, c) + ":"; // "C:"
        info.model = "";
        info.bus = "";
        info.type = "";

        std::string volPath = "\\\\.\\" + info.name; // \\.\C:
        HANDLE hVol = CreateFileA(volPath.c_str(), 0,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  NULL, OPEN_EXISTING, 0, NULL);
        if (hVol == INVALID_HANDLE_VALUE) {
            drives.push_back(info);
            continue;
        }

        STORAGE_PROPERTY_QUERY query{};
        query.PropertyId = StorageDeviceSeekPenaltyProperty;
        query.QueryType = PropertyStandardQuery;
        DEVICE_SEEK_PENALTY_DESCRIPTOR seekPenalty{};
        DWORD bytesReturned = 0;
        bool isSSD = false;
        if (DeviceIoControl(hVol, IOCTL_STORAGE_QUERY_PROPERTY,
                            &query, sizeof(query),
                            &seekPenalty, sizeof(seekPenalty),
                            &bytesReturned, NULL)) {
            isSSD = !seekPenalty.IncursSeekPenalty;
        }

        STORAGE_PROPERTY_QUERY query2{};
        query2.PropertyId = StorageDeviceProperty;
        query2.QueryType = PropertyStandardQuery;
        std::vector<BYTE> buffer(2048);
        if (DeviceIoControl(hVol, IOCTL_STORAGE_QUERY_PROPERTY,
                            &query2, sizeof(query2),
                            buffer.data(), (DWORD)buffer.size(),
                            &bytesReturned, NULL)) {
            auto* devDesc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buffer.data());
            if (devDesc->BusType == BusTypeNvme) {
                info.bus = "nvme";
                info.type = "NVMe SSD";
            } else if (devDesc->BusType == BusTypeAta || devDesc->BusType == BusTypeSata) {
                info.bus = "sata";
                info.type = isSSD ? "SATA SSD" : "HDD";
            } else if (devDesc->BusType == BusTypeUsb) {
                info.bus = "usb";
                info.type = "USB Storage";
            } else {
                info.bus = "other";
                info.type = isSSD ? "SSD" : "HDD";
            }

            if (devDesc->ProductIdOffset != 0 && devDesc->ProductIdOffset < buffer.size()) {
                const char* p = reinterpret_cast<const char*>(buffer.data() + devDesc->ProductIdOffset);
                info.model = std::string(p);
            }
        } else {
            if (driveType == DRIVE_REMOVABLE) {
                info.bus = "usb";
                info.type = "USB Storage";
            } else {
                info.bus = "other";
                info.type = isSSD ? "SSD" : "HDD";
            }
        }

        CloseHandle(hVol);
        drives.push_back(info);
    }
    return drives;
}

std::string driveLetterToPhysicalDrive(const std::string& driveLetter) {
    if (driveLetter.size() < 2) return {};

    std::string volPath = "\\\\.\\" + driveLetter; // \\.\C:
    HANDLE hVol = CreateFileA(volPath.c_str(),
                              0,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING, 0, NULL);
    if (hVol == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Failed to open volume " << volPath << " (err=" << GetLastError() << ")\n";
        return {};
    }

    const DWORD bufSize = 4096;
    std::vector<BYTE> buf(bufSize);
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        hVol,
        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
        NULL, 0,
        buf.data(), bufSize,
        &bytesReturned,
        NULL
    );

    if (!ok) {
        std::cerr << "[!] IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS failed (err=" << GetLastError() << ")\n";
        CloseHandle(hVol);
        return {};
    }

    auto* ext = reinterpret_cast<VOLUME_DISK_EXTENTS*>(buf.data());
    if (ext->NumberOfDiskExtents < 1) {
        std::cerr << "[!] No disk extents for " << volPath << "\n";
        CloseHandle(hVol);
        return {};
    }

    DWORD diskNumber = ext->Extents[0].DiskNumber;
    CloseHandle(hVol);

    return std::string("\\\\.\\PhysicalDrive") + std::to_string(diskNumber);
}


#elif defined(__linux__)
#include <dirent.h>
#include <fstream>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

static std::string readSysfs(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return {};
    std::string val;
    std::getline(f, val);
    return val;
}

std::vector<DriveInfo> getDrives() {
    std::vector<DriveInfo> drives;
    DIR* dir = opendir("/sys/block");
    if (!dir) return drives;
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string devName = entry->d_name;
        if (devName == "." || devName == ".." || devName.find("loop") == 0)
            continue;

        std::string sysPath = std::string("/sys/block/") + devName;
        if (access((sysPath + "/device").c_str(), F_OK) != 0) continue;

        DriveInfo info;
        info.name = "/dev/" + devName;

        bool looksLikePartition = false;
        if (!devName.empty() && isdigit(devName.back())) looksLikePartition = true;
        if (looksLikePartition) continue;

        info.model = readSysfs(sysPath + "/device/model");
        std::string rotational = readSysfs(sysPath + "/queue/rotational");
        bool isSSD = (rotational == "0");

        char buf[PATH_MAX];
        ssize_t len = readlink((sysPath + "/device/subsystem").c_str(), buf, sizeof(buf)-1);
        if (len > 0) {
            buf[len] = '\0';
            std::string subsys = buf;
            if (subsys.find("nvme") != std::string::npos) {
                info.bus = "nvme";
                info.type = "NVMe SSD";
            } else if (subsys.find("ata") != std::string::npos) {
                info.bus = "sata";
                info.type = isSSD ? "SATA SSD" : "HDD";
            } else if (subsys.find("usb") != std::string::npos) {
                info.bus = "usb";
                info.type = "USB Storage";
            } else {
                info.bus = "other";
                info.type = isSSD ? "SSD" : "HDD";
            }
        } else {
            info.bus = "other";
            info.type = isSSD ? "SSD" : "HDD";
        }

        drives.push_back(info);
    }
    closedir(dir);
    return drives;
}
#else
std::vector<DriveInfo> getDrives() { return {}; }
#endif

// ---------------- Sanitization helper ----------------
void sanitizeDrive(const DriveInfo& d, bool dryRun = false) {
    std::string targetPath = d.name;

#ifdef _WIN32
    if (d.name.size() >= 2 && d.name[1] == ':') {
        std::string physical = driveLetterToPhysicalDrive(d.name);
        if (physical.empty()) {
            std::cerr << "[!] Could not map " << d.name << " to physical drive. Skipping.\n";
            return;
        }
        targetPath = physical;

        // Auto-dismount USB volumes before sanitizing
        if (d.bus == "usb") {
            std::string volPath = "\\\\.\\" + d.name; // e.g., \\.\E:
            std::cout << "[*] Preparing USB drive: dismounting volume " << volPath << "\n";
            dismountVolume(volPath);
        }
    }
#endif

    std::cout << "[+] Sanitizing: " << d.name;
    if (targetPath != d.name) std::cout << " -> " << targetPath;
    std::cout << " (" << d.type << ")";
    if (!d.model.empty()) std::cout << " [" << d.model << "]";
    if (!d.bus.empty())   std::cout << " [bus=" << d.bus << "]";
    std::cout << "\n";

    if (dryRun) {
        std::cout << "    (dry-run) would run:";
        if (d.bus == "nvme") {
            std::cout << " nvmeFormatNVM(" << targetPath << ", 1)\n";
        } else if (d.bus == "sata") {
            std::cout << " ataSecureErase(" << targetPath << ")\n";
        } else {
            std::cout << " overwriteZero(" << targetPath << ")\n";
        }
        return;
    }

    bool ok = false;
    std::string method;
    if (d.bus == "nvme") {
        ok = nvmeFormatNVM(targetPath, 1);
        method = "nvmeFormatNVM";
    } else if (d.bus == "sata") {
        ok = ataSecureErase(targetPath);
        method = "ataSecureErase";
        if (!ok) {
            std::cerr << "[!] ataSecureErase failed, falling back to overwrite.\n";
            ok = overwriteZero(targetPath);
            method = "overwriteZero";
        }
    } else {
        ok = overwriteZero(targetPath);
        method = "overwriteZero";
    }

    if (ok) {
        std::cout << "[+] Sanitization succeeded for " << targetPath << "\n";
    } else {
        std::cerr << "[!] Sanitization FAILED for " << targetPath << "\n";
    }

    logSanitization(d, method, ok);
}

// ---------------- Main ----------------
int main(int argc, char* argv[]) {
    bool dryRun = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--dry-run" || a == "-n") dryRun = true;
    }

    auto drives = getDrives();
    if (drives.empty()) {
        std::cout << "No drives detected.\n";
        return 0;
    }

    std::cout << "Detected drives:\n";
    for (size_t i = 0; i < drives.size(); ++i) {
        const auto& d = drives[i];
        std::cout << "  [" << i << "] " << d.name << " -> " << d.type;
        if (!d.model.empty()) std::cout << " (" << d.model << ")";
        if (!d.bus.empty())   std::cout << " [bus=" << d.bus << "]";
        std::cout << "\n";
    }

    if (dryRun) {
        std::cout << "\nRunning in dry-run mode. No destructive actions will be performed.\n";
    } else {
        std::cout << "\n[!] WARNING: This will DESTROY ALL DATA on selected drives.\n";
    }

    std::cout << "Select drives to sanitize (e.g. 0 2 3) or 'all': ";
    std::string line;
    std::getline(std::cin, line);
    if (line.empty()) {
        std::cout << "No selection given. Exiting.\n";
        return 0;
    }

    std::vector<int> selections;
    if (line == "all") {
        for (size_t i = 0; i < drives.size(); ++i) selections.push_back((int)i);
    } else {
        std::istringstream iss(line);
        int idx;
        while (iss >> idx) {
            if (idx >= 0 && (size_t)idx < drives.size()) selections.push_back(idx);
            else std::cerr << "[!] Ignoring invalid index " << idx << "\n";
        }
    }
    if (selections.empty()) {
        std::cout << "No valid selection. Exiting.\n";
        return 0;
    }

    std::cout << "Type 'yes' to confirm and proceed: ";
    std::string confirm;
    std::getline(std::cin, confirm);
    if (confirm != "yes") {
        std::cout << "Aborted by user.\n";
        return 0;
    }

    for (int idx : selections) {
        sanitizeDrive(drives[idx], dryRun);
    }

    return 0;
}
