// SanitizeDrives.cpp
// Cross-platform drive detection + sanitization + certificate generation
// WARNING: This code performs destructive operations. Use only on test systems.

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <fstream>
#include <ctime>

#include "sanitize.h"

// ----- Drive info -----
struct DriveInfo {
    std::string name;   // Windows: "C:", Linux: "/dev/sda"
    std::string type;   // HDD, SATA SSD, NVMe SSD, USB, etc.
    std::string model;  // Vendor/model if available
    std::string bus;    // sata, nvme, usb, etc.
};

struct WipeResult {
    DriveInfo drive;
    std::string method;
    bool success;
};

// ----- OpenSSL includes -----
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <vector>

// ----- JSON includes -----
#include <nlohmann/json.hpp>
using json = nlohmann::json;

// ----- Signing function -----
std::string signJSON(const std::string& path, const std::string& privKeyPath) {
    // Read file
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        std::cerr << "[!] Could not open JSON file for signing\n";
        return {};
    }
    std::ostringstream ss; ss << in.rdbuf();
    std::string data = ss.str();

    // Load key
    FILE* keyFile = fopen(privKeyPath.c_str(), "r");
    if (!keyFile) {
        std::cerr << "[!] Could not open private key file\n";
        return {};
    }
    EVP_PKEY* pkey = PEM_read_PrivateKey(keyFile, NULL, NULL, NULL);
    fclose(keyFile);
    if (!pkey) {
        std::cerr << "[!] Failed to read private key\n";
        return {};
    }

    // Hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)data.c_str(), data.size(), hash);

    // Sign
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_SignInit(ctx, EVP_sha256());
    EVP_SignUpdate(ctx, hash, SHA256_DIGEST_LENGTH);

    std::vector<unsigned char> sig(EVP_PKEY_size(pkey));
    unsigned int sigLen = 0;
    EVP_SignFinal(ctx, sig.data(), &sigLen, pkey);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    // Base64 encode
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);
    BIO_write(b64, sig.data(), sigLen);
    BIO_flush(b64);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string out(bptr->data, bptr->length);
    BIO_free_all(b64);

    return out;
}

// ----- JSON certificate -----
void saveBatchCertificateJSON(const std::vector<WipeResult>& results, const std::string& sig) {
    json j;
    std::time_t now = std::time(nullptr);
    j["timestamp"] = std::asctime(std::localtime(&now));
    j["signature"] = sig;

    for (const auto& r : results) {
        json entry;
        entry["drive_name"] = r.drive.name;
        entry["model"] = r.drive.model;
        entry["bus"] = r.drive.bus;
        entry["type"] = r.drive.type;
        entry["method"] = r.method;
        entry["result"] = r.success ? "SUCCESS" : "FAIL";
        j["drives"].push_back(entry);
    }

    std::ofstream out("wipe_certificate.json");
    out << j.dump(4);
    std::cout << "[+] JSON certificate written to wipe_certificate.json\n";
}

#ifdef _WIN32
// ---------------- Windows drive detection (same as your version) ----------------
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <vector>

// ... (Windows getDrives + driveLetterToPhysicalDrive code unchanged) ...
static std::string trimTrailingBackslash(const std::string& s) {
    if (!s.empty() && (s.back() == '\\' || s.back() == '/')) return s.substr(0, s.size()-1);
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
        info.name = std::string(1, c) + ":"; // store as "C:"
        info.model = "";
        info.bus = "";
        info.type = ""; // we try to fill later

        // Try to open volume to query storage properties
        std::string volPath = "\\\\.\\" + info.name; // \\.\C:
        HANDLE hVol = CreateFileA(volPath.c_str(), 0,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  NULL, OPEN_EXISTING, 0, NULL);
        if (hVol == INVALID_HANDLE_VALUE) {
            drives.push_back(info);
            continue;
        }

        // Query StorageDeviceSeekPenaltyProperty to guess SSD vs HDD
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

        // Query device descriptor for BusType & ProductId
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
            // fallback: classify by drive type
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

// Map logical drive (e.g. "C:") to physical drive path (e.g. "\\.\PhysicalDrive0")
// Returns empty string on failure.
std::string driveLetterToPhysicalDrive(const std::string& driveLetter) {
    // Expect input like "C:"
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

    // DeviceIoControl needs a buffer that can hold multiple extents.
    // We'll allocate a reasonable buffer (4 KB) that covers multiple extents.
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

    // Cast to structure (buffer large enough)
    auto* ext = reinterpret_cast<VOLUME_DISK_EXTENTS*>(buf.data());
    if (ext->NumberOfDiskExtents < 1) {
        std::cerr << "[!] No disk extents for " << volPath << "\n";
        CloseHandle(hVol);
        return {};
    }

    // Choose first extent's DiskNumber
    DWORD diskNumber = ext->Extents[0].DiskNumber;
    CloseHandle(hVol);

    return std::string("\\\\.\\PhysicalDrive") + std::to_string(diskNumber);
}

#elif defined(__linux__)
// ---------------- Linux drive detection (same as your version) ----------------
#include <dirent.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

// ... (Linux getDrives code unchanged) ...
static std::string readSysfs(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return {};
    std::string val;
    std::getline(f, val);
    return val;
}

// Returns true if /sys/block/<dev>/partition exists -> indicates it's a partition
static bool isPartitionSysfs(const std::string& devPath) {
    struct stat st;
    return stat(devPath.c_str(), &st) == 0;
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

        // Skip partition devices (e.g., sda1, nvme0n1p1). We only want whole devices (sda, nvme0n1).
        // For most devices, the sysfs entry /sys/block/<dev>/partition does not exist for whole-device.
        // To detect partition entries we check if the name contains digits at the end in a way that indicates a partition.
        // Simpler robust approach: check for existence of "/sys/block/<dev>/partition" file — partitions have a "partition" file under their sysfs node.
        std::string sysPath = std::string("/sys/block/") + devName;
        // If this entry itself is a partition directory (rare for /sys/block), skip.
        // However, some virtuals like "mmcblk0p1" aren't in /sys/block top-level; the top-level contains whole devices.
        // We'll do a more definitive check: only include top-level block devices (those that have /sys/block/<dev>/device)
        if (access((sysPath + "/device").c_str(), F_OK) != 0) {
            // skip entries that don't have device node
            continue;
        }

        DriveInfo info;
        info.name = "/dev/" + devName;

        // Skip partition-like names: sda1, nvme0n1p1, mmcblk0p1
        // We can skip any name that contains a digit at the end (simple heuristic).
        bool looksLikePartition = false;
        // if last char is digit, or name contains 'p' + digit at end for nvme/mmcblk
        if (!devName.empty() && isdigit(devName.back())) looksLikePartition = true;
        if (looksLikePartition) continue;

        std::string devPath = sysPath;
        info.model = readSysfs(devPath + "/device/model");
        std::string rotational = readSysfs(devPath + "/queue/rotational");
        bool isSSD = (rotational == "0");

        // Determine subsystem from symlink
        char buf[PATH_MAX];
        ssize_t len = readlink((devPath + "/device/subsystem").c_str(), buf, sizeof(buf)-1);
        if (len > 0) {
            buf[len] = '\0';
            std::string subsys = buf;
            if (subsys.find("nvme") != std::string::npos) {
                info.bus = "nvme";
                info.type = "NVMe SSD";
            } else if (subsys.find("ata") != std::string::npos || subsys.find("ata") != std::string::npos) {
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
WipeResult sanitizeDrive(const DriveInfo& d, bool dryRun = false) {
    std::string targetPath = d.name; // default pass-through
    std::string method;
    bool ok = false;

#ifdef _WIN32
    if (d.name.size() >= 2 && d.name[1] == ':') {
        std::string physical = driveLetterToPhysicalDrive(d.name);
        if (!physical.empty()) targetPath = physical;
    }
#endif

    std::cout << "[+] Sanitizing: " << d.name;
    if (targetPath != d.name) std::cout << " -> " << targetPath;
    std::cout << " (" << d.type << ")";
    if (!d.model.empty()) std::cout << " [" << d.model << "]";
    if (!d.bus.empty())   std::cout << " [bus=" << d.bus << "]";
    std::cout << "\n";

    if (dryRun) {
        if (d.bus == "nvme") method = "NVMe Format NVM (Purge)";
        else if (d.bus == "sata") method = "ATA Secure Erase (Purge)";
        else method = "Overwrite Zero (Clear)";
        std::cout << "    (dry-run) would run: " << method << "\n";
        return {d, method, true};
    }

    if (d.bus == "nvme") {
        method = "NVMe Format NVM (Purge)";
        ok = nvmeFormatNVM(targetPath, 1);
    } else if (d.bus == "sata") {
        method = "ATA Secure Erase (Purge)";
        ok = ataSecureErase(targetPath);
        if (!ok) {
            std::cerr << "[!] ataSecureErase failed, falling back to overwrite\n";
            method = "Overwrite Zero (Clear)";
            ok = overwriteZero(targetPath);
        }
    } else {
        method = "Overwrite Zero (Clear)";
        ok = overwriteZero(targetPath);
        if (ok) ok = verifyZeroed(targetPath);
    }

    if (ok) std::cout << "[+] Sanitization succeeded for " << targetPath << "\n";
    else std::cerr << "[!] Sanitization FAILED for " << targetPath << "\n";

    return {d, method, ok};
}

// ---------------- Main ----------------
int main(int argc, char* argv[]) {
    bool dryRun = false;
    for (int i=1;i<argc;++i) {
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
        const auto & d = drives[i];
        std::cout << "  [" << i << "] " << d.name << " -> " << d.type;
        if (!d.model.empty()) std::cout << " (" << d.model << ")";
        if (!d.bus.empty())   std::cout << " [bus=" << d.bus << "]";
        std::cout << "\n";
    }

    if (dryRun) std::cout << "\nRunning in dry-run mode. No destructive actions will be performed.\n";
    else std::cout << "\n[!] WARNING: This will DESTROY ALL DATA on selected drives.\n";

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

    std::vector<WipeResult> results;
    for (int idx : selections) {
        results.push_back(sanitizeDrive(drives[idx], dryRun));
    }

    // ----- Certificate generation -----
    saveBatchCertificateJSON(results, "");
    std::string sig = signJSON("wipe_certificate.json", "private.pem");
    saveBatchCertificateJSON(results, sig);
    std::cout << "[+] Wipe certificate generated (JSON). Use make_cert.py to render PDF.\n";

    return 0;
}
