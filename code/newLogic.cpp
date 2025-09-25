#include <iostream>
#include <string>
#include <vector>

struct DriveInfo {
    std::string name;   // Drive letter (Windows) or device name (Linux)
    std::string type;   // HDD, SATA SSD, NVMe SSD, USB, etc.
    std::string model;  // Vendor/model if available
    std::string bus;    // sata, nvme, usb, etc.
};

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>

std::vector<DriveInfo> getDrives() {
    std::vector<DriveInfo> drives;

    DWORD driveMask = GetLogicalDrives();
    for (char c = 'A'; c <= 'Z'; ++c) {
        if (!(driveMask & (1 << (c - 'A')))) continue;

        std::string root = std::string(1, c) + ":\\";
        UINT driveType = GetDriveType(root.c_str());
        if (driveType != DRIVE_FIXED && driveType != DRIVE_REMOVABLE)
            continue;

        std::string devicePath = "\\\\.\\" + root.substr(0, 2); // \\.\C:
        HANDLE hDevice = CreateFileA(
            devicePath.c_str(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );

        if (hDevice == INVALID_HANDLE_VALUE) continue;

        DriveInfo info;
        info.name = root.substr(0, 2); // e.g., "C:"

        // --- Check if SSD (seek penalty) ---
        STORAGE_PROPERTY_QUERY query{};
        query.PropertyId = StorageDeviceSeekPenaltyProperty;
        query.QueryType = PropertyStandardQuery;
        DEVICE_SEEK_PENALTY_DESCRIPTOR seekPenalty{};
        DWORD bytesReturned = 0;
        bool isSSD = false;

        if (DeviceIoControl(hDevice,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &query, sizeof(query),
            &seekPenalty, sizeof(seekPenalty),
            &bytesReturned, NULL)) {
            isSSD = !seekPenalty.IncursSeekPenalty;
        }

        // --- Get bus type + model name ---
        STORAGE_PROPERTY_QUERY query2{};
        query2.PropertyId = StorageDeviceProperty;
        query2.QueryType = PropertyStandardQuery;

        BYTE buffer[1024] = {};
        auto* devDesc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buffer);

        if (DeviceIoControl(hDevice,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &query2, sizeof(query2),
            buffer, sizeof(buffer),
            &bytesReturned, NULL)) {

            // --- Bus type ---
            switch (devDesc->BusType) {
            case BusTypeNvme:
                info.bus = "nvme";
                info.type = "NVMe SSD";
                break;
            case BusTypeAta:
            case BusTypeSata:
                info.bus = "sata";
                info.type = isSSD ? "SATA SSD" : "HDD";
                break;
            case BusTypeUsb:
                info.bus = "usb";
                info.type = "USB Storage";
                break;
            default:
                info.bus = "other";
                info.type = isSSD ? "SSD" : "HDD";
                break;
            }

            // --- Model string (if available) ---
            if (devDesc->ProductIdOffset != 0 &&
                devDesc->ProductIdOffset < sizeof(buffer)) {
                info.model = reinterpret_cast<char*>(buffer + devDesc->ProductIdOffset);
            }
        }

        CloseHandle(hDevice);
        drives.push_back(info);
    }

    return drives;
}

#elif defined(__linux__)

#include <dirent.h>
#include <fstream>
#include <unistd.h>

std::string readSysfs(const std::string& path) {
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

        // skip "." ".." and loop devices
        if (devName == "." || devName == ".." || devName.find("loop") == 0)
            continue;

        DriveInfo info;
        info.name = "/dev/" + devName;

        std::string devPath = std::string("/sys/block/") + devName;

        // Model (if available)
        info.model = readSysfs(devPath + "/device/model");

        // Rotational flag: 1 = HDD, 0 = SSD
        std::string rotational = readSysfs(devPath + "/queue/rotational");
        bool isSSD = (rotational == "0");

        // Bus type (look at /sys/block/<dev>/device/subsystem)
        char buf[PATH_MAX];
        ssize_t len = readlink((devPath + "/device/subsystem").c_str(), buf, sizeof(buf)-1);
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
        }

        drives.push_back(info);
    }

    closedir(dir);
    return drives;
}

#else
std::vector<DriveInfo> getDrives() {
    return {}; // unsupported platform
}
#endif

int main() {
    auto drives = getDrives();
    for (const auto& d : drives) {
        std::cout << d.name << " -> " << d.type;
        if (!d.model.empty()) std::cout << " (" << d.model << ")";
        if (!d.bus.empty())   std::cout << " [bus=" << d.bus << "]";
        std::cout << "\n";
    }
    return 0;
}
