// sanitize.cpp
// Cross-platform sanitization + verification functions.

#include "sanitize.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <ctime>
#include <random>

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#include <memory>
#include <cstdint>

// --- Open Physical Drive ---
static HANDLE openPhysicalDrive(const std::string& physicalPath) {
    HANDLE h = CreateFileA(
        physicalPath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if (h == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] CreateFile failed for " << physicalPath << " (err=" << GetLastError() << ")\n";
    }
    return h;
}

// --- Overwrite with zeros (Clear) ---
bool overwriteZero(const std::string& physicalPath) {
    HANDLE h = openPhysicalDrive(physicalPath);
    if (h == INVALID_HANDLE_VALUE) return false;

    DISK_GEOMETRY_EX geom;
    DWORD bytes = 0;
    if (!DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                         NULL, 0, &geom, sizeof(geom), &bytes, NULL)) {
        std::cerr << "[!] IOCTL_DISK_GET_DRIVE_GEOMETRY_EX failed (err=" << GetLastError() << ")\n";
        CloseHandle(h);
        return false;
    }

    unsigned long long totalBytes = static_cast<unsigned long long>(geom.DiskSize.QuadPart);
    std::cout << "[*] OverwriteZero: wiping " << physicalPath << " (" << (totalBytes / (1024ULL*1024ULL*1024ULL)) << " GB)\n";

    const DWORD BUF_SIZE = 4 * 1024 * 1024; // 4 MiB buffer
    std::unique_ptr<char[]> buffer(new char[BUF_SIZE]());
    unsigned long long written = 0;

    LARGE_INTEGER offset; offset.QuadPart = 0;
    if (!SetFilePointerEx(h, offset, NULL, FILE_BEGIN)) {
        std::cerr << "[!] SetFilePointerEx failed (err=" << GetLastError() << ")\n";
        CloseHandle(h);
        return false;
    }

    while (written < totalBytes) {
        DWORD toWrite = BUF_SIZE;
        if (totalBytes - written < BUF_SIZE) toWrite = static_cast<DWORD>(totalBytes - written);

        DWORD actuallyWritten = 0;
        if (!WriteFile(h, buffer.get(), toWrite, &actuallyWritten, NULL) || actuallyWritten != toWrite) {
            std::cerr << "[!] WriteFile failed at " << written << " bytes (err=" << GetLastError() << ")\n";
            CloseHandle(h);
            return false;
        }

        written += actuallyWritten;
        if ((written / (1024ULL*1024ULL*1024ULL)) != ((written - actuallyWritten) / (1024ULL*1024ULL*1024ULL))) {
            std::cout << "   -> " << (written / (1024ULL*1024ULL*1024ULL)) << " GB written\n";
        }
    }

    FlushFileBuffers(h);
    CloseHandle(h);
    std::cout << "[+] OverwriteZero: done for " << physicalPath << "\n";
    return true;
}

// Stubs for ATA/NVMe unless built with MSVC + Windows SDK
bool ataSecureErase(const std::string& physicalPath) {
    std::cerr << "[!] ATA Secure Erase not supported in this build (requires Windows SDK / MSVC).\n";
    (void)physicalPath;
    return false;
}
bool nvmeFormatNVM(const std::string& physicalPath, uint8_t ses) {
    std::cerr << "[!] NVMe Format NVM not supported in this build (requires Windows SDK / MSVC).\n";
    (void)physicalPath;
    (void)ses;
    return false;
}

// --- Verification ---
bool verifyZeroed(const std::string& devPath, size_t checks) {
    HANDLE h = openPhysicalDrive(devPath);
    if (h == INVALID_HANDLE_VALUE) return false;

    const DWORD blockSize = 4096;
    std::vector<char> buffer(blockSize);
    std::random_device rd;
    std::mt19937 gen(rd());

    // Use up to 1 GB by default
    std::uniform_int_distribution<unsigned long long> dist(0, 1024ULL*1024ULL*1024ULL);

    for (size_t i = 0; i < checks; i++) {
        LARGE_INTEGER offset;
        offset.QuadPart = dist(gen);
        if (!SetFilePointerEx(h, offset, NULL, FILE_BEGIN)) continue;
        DWORD readBytes = 0;
        if (!ReadFile(h, buffer.data(), blockSize, &readBytes, NULL)) continue;
        for (DWORD j = 0; j < readBytes; j++) {
            if (buffer[j] != 0) {
                std::cerr << "[!] Verification failed at offset " << offset.QuadPart << "\n";
                CloseHandle(h);
                return false;
            }
        }
    }
    CloseHandle(h);
    std::cout << "[+] Verification passed for " << devPath << "\n";
    return true;
}

#elif defined(__linux__)
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstring>

// --- Overwrite with zeros (Clear) ---
bool overwriteZero(const std::string& devPath) {
    std::string cmd = "dd if=/dev/zero of=" + devPath + " bs=4M status=progress conv=fsync";
    std::cout << "[*] Running: " << cmd << "\n";
    int rc = system(cmd.c_str());
    return rc == 0;
}

// --- ATA Secure Erase (Purge) ---
bool ataSecureErase(const std::string& devPath) {
    std::string cmd = "hdparm --security-erase NULL " + devPath;
    std::cout << "[*] Running: " << cmd << "\n";
    int rc = system(cmd.c_str());
    return rc == 0;
}

// --- NVMe Format NVM (Purge) ---
bool nvmeFormatNVM(const std::string& devPath, uint8_t ses) {
    std::string cmd = "nvme format " + devPath + " -s " + std::to_string(ses);
    std::cout << "[*] Running: " << cmd << "\n";
    int rc = system(cmd.c_str());
    return rc == 0;
}

// --- Verification ---
bool verifyZeroed(const std::string& devPath, size_t checks) {
    int fd = open(devPath.c_str(), O_RDONLY);
    if (fd < 0) {
        std::cerr << "[!] Could not open " << devPath << " for verification\n";
        return false;
    }

    const size_t blockSize = 4096;
    std::vector<char> buffer(blockSize);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned long long> dist(0, 1024ULL*1024ULL*1024ULL);

    for (size_t i = 0; i < checks; i++) {
        off_t offset = dist(gen);
        if (lseek(fd, offset, SEEK_SET) < 0) continue;
        ssize_t r = read(fd, buffer.data(), blockSize);
        if (r > 0) {
            for (ssize_t j = 0; j < r; j++) {
                if (buffer[j] != 0) {
                    std::cerr << "[!] Verification failed at offset " << offset << "\n";
                    close(fd);
                    return false;
                }
            }
        }
    }
    close(fd);
    std::cout << "[+] Verification passed for " << devPath << "\n";
    return true;
}

#else
bool overwriteZero(const std::string&) { return false; }
bool ataSecureErase(const std::string&) { return false; }
bool nvmeFormatNVM(const std::string&, uint8_t) { return false; }
bool verifyZeroed(const std::string&, size_t) { return false; }
#endif

// --- Logging ---
void logSanitization(const DriveInfo& d, const std::string& method, bool success) {
    std::ofstream log("sanitize_log.txt", std::ios::app);
    std::time_t now = std::time(nullptr);

    log << "[" << std::asctime(std::localtime(&now)) << "] "
        << "Drive: " << d.name
        << " (" << d.model << ")"
        << " Bus: " << d.bus
        << " Method: " << method
        << " Result: " << (success ? "SUCCESS" : "FAIL")
        << "\n";
}
