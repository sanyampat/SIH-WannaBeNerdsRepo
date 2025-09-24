#include <windows.h>
#include <winioctl.h>
#include <iostream>
#include <string>
#include <vector>

using namespace std;

string GetDriveTypeDetailed(const std::string& rootPath) {
    std::string devicePath = "\\\\.\\" + rootPath.substr(0, 2); // e.g., C: -> \\.\C:
    HANDLE hDevice = CreateFileA(
        devicePath.c_str(),
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        return "Unknown";
    }

    // First: check seek penalty (HDD vs SSD)
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

    // Second: check bus type (SATA, NVMe, USB, etc.)
    STORAGE_PROPERTY_QUERY query2{};
    query2.PropertyId = StorageDeviceProperty;
    query2.QueryType = PropertyStandardQuery;

    BYTE buffer[1024] = {};
    STORAGE_DEVICE_DESCRIPTOR* devDesc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buffer);

    if (DeviceIoControl(hDevice,
        IOCTL_STORAGE_QUERY_PROPERTY,
        &query2, sizeof(query2),
        buffer, sizeof(buffer),
        &bytesReturned, NULL)) {
        switch (devDesc->BusType) {
        case BusTypeNvme:
            CloseHandle(hDevice);
            return "NVMe SSD";
        case BusTypeAta:
        case BusTypeSata:
            CloseHandle(hDevice);
            return isSSD ? "SATA SSD" : "HDD";
        case BusTypeUsb:
            CloseHandle(hDevice);
            return "USB Storage";
        default:
            CloseHandle(hDevice);
            return isSSD ? "SSD (other bus)" : "HDD (other bus)";
        }
    }

    CloseHandle(hDevice);
    return isSSD ? "SSD" : "HDD";
}

vector<string> GetAllDrivesInfo() {
    vector<string> results;
    DWORD drives = GetLogicalDrives();

    for (char c = 'A'; c <= 'Z'; ++c) {
        if (drives & (1 << (c - 'A'))) {
            std::string root = std::string(1, c) + ":\\";
            UINT type = GetDriveType(root.c_str());
            std::string info = root + " -> ";

            switch (type) {
            case DRIVE_FIXED:
                info += "Fixed drive (" + GetDriveTypeDetailed(root) + ")";
                break;
            case DRIVE_REMOVABLE:
                info += "Removable drive (USB)";
                break;
            case DRIVE_CDROM:
                info += "CD/DVD";
                break;
            case DRIVE_REMOTE:
                info += "Network drive";
                break;
            default:
                info += "Other/Unknown";
                break;
            }
            results.push_back(info);
        }
    }

    return results;
}

// Example usage
int main() {
    auto drives = GetAllDrivesInfo();
    for (const auto& d : drives) {
        cout << d << "\n";
    }
    return 0;
}
