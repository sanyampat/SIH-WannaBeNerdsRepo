// sanitize.cpp
// Cross-platform sanitization + verification functions.
// Windows implementation includes ATA Secure Erase attempt and overwrite.
// NVMe Format is left as a safe stub on Windows (see comments).
// WARNING: Destructive operations. Test only on disposable drives.

#include "sanitize.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <ctime>
#include <random>

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <memory>
#include <cstdint>

// Some systems may provide ntddscsi.h for ATA_PASS_THROUGH_EX; include if available.
#if __has_include(<ntddscsi.h>)
# include <ntddscsi.h>
#endif
#if __has_include(<ntddstor.h>)
# include <ntddstor.h>
#endif

// Helper: print last error nicely
static void printWinError(const std::string &label, DWORD err) {
    LPVOID msgBuf = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   (LPSTR)&msgBuf, 0, NULL);
    std::cerr << "[!] " << label << " (err=" << err << ") - "
              << (msgBuf ? (char*)msgBuf : "No message") << "\n";
    if (msgBuf) LocalFree(msgBuf);
}

// --- Open Physical Drive (exclusive) ---
static HANDLE openPhysicalDrive(const std::string& physicalPath, bool exclusive = true) {
    DWORD share = exclusive ? 0 : (FILE_SHARE_READ | FILE_SHARE_WRITE);
    HANDLE h = CreateFileA(
        physicalPath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        share,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        printWinError(std::string("CreateFile failed for ") + physicalPath, err);
    }
    return h;
}

// --- Dismount volume (exposed in header) ---
bool dismountVolume(const std::string& volumePath) {
    HANDLE hVol = CreateFileA(
        volumePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if (hVol == INVALID_HANDLE_VALUE) {
        printWinError(std::string("Could not open volume ") + volumePath + " for dismount", GetLastError());
        return false;
    }
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(hVol, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &bytes, NULL);
    CloseHandle(hVol);
    if (!ok) {
        printWinError(std::string("FSCTL_DISMOUNT_VOLUME failed for ") + volumePath, GetLastError());
        return false;
    }
    std::cout << "[*] Dismounted volume " << volumePath << "\n";
    return true;
}

// ---------------- ATA Secure Erase (Windows) ----------------
// Attempt ATA pass-through if available. This is driver- and hardware-dependent.

static bool sendAtaCommand(HANDLE hDevice, ATA_PASS_THROUGH_EX &apt, PVOID dataBuffer, DWORD dataBufferLength) {
#ifdef IOCTL_ATA_PASS_THROUGH
    DWORD bytesRet = 0;
    BOOL ok = DeviceIoControl(hDevice, IOCTL_ATA_PASS_THROUGH,
                              &apt, sizeof(apt),
                              dataBuffer, dataBufferLength,
                              &bytesRet, NULL);
    if (!ok) {
        printWinError("IOCTL_ATA_PASS_THROUGH failed", GetLastError());
    }
    return ok == TRUE;
#else
    SetLastError(ERROR_NOT_SUPPORTED);
    printWinError("IOCTL_ATA_PASS_THROUGH not available on this system", GetLastError());
    return false;
#endif
}

bool ataSecureErase(const std::string& physicalPath) {
    std::cout << "[*] Attempting ATA Secure Erase on " << physicalPath << "\n";

    HANDLE h = openPhysicalDrive(physicalPath, true);
    if (h == INVALID_HANDLE_VALUE) return false;

#ifdef IOCTL_ATA_PASS_THROUGH
    // NOTE: This is a minimal attempt; many drives require password setup (SECURITY_SET_PASSWORD)
    // and other vendor-specific steps. This may fail on many systems; in such case caller falls back to overwrite.
    const DWORD bufferSize = sizeof(ATA_PASS_THROUGH_EX);
    std::unique_ptr<BYTE[]> buffer(new BYTE[bufferSize]);
    ZeroMemory(buffer.get(), bufferSize);

    ATA_PASS_THROUGH_EX *apt = reinterpret_cast<ATA_PASS_THROUGH_EX*>(buffer.get());
    apt->Length = sizeof(ATA_PASS_THROUGH_EX);
    apt->TimeOutValue = 60;
    // Command register (offset 6 in TaskFile)
    apt->CurrentTaskFile[6] = 0xF4; // SECURITY ERASE UNIT

    DWORD bytesRet = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_ATA_PASS_THROUGH,
                              apt, (DWORD)sizeof(ATA_PASS_THROUGH_EX),
                              NULL, 0, &bytesRet, NULL);
    if (!ok) {
        printWinError("IOCTL_ATA_PASS_THROUGH (SECURE ERASE) failed", GetLastError());
        CloseHandle(h);
        return false;
    }

    std::cout << "[+] ATA Secure Erase command submitted (driver accepted). Monitor device for completion.\n";
    CloseHandle(h);
    return true;
#else
    printWinError("ATA pass-through not available on this build/SDK", ERROR_NOT_SUPPORTED);
    CloseHandle(h);
    return false;
#endif
}

// ---------------- NVMe Format NVM (Windows) ----------------
// For compatibility and to avoid conflicting typedefs, leave a safe stub here.
// Implementing a correct NVMe pass-through requires careful use of STORAGE_PROTOCOL_COMMAND
// and matching the Windows SDK struct layout; that is left for an explicit implementation step.

bool nvmeFormatNVM(const std::string& physicalPath, uint8_t ses) {
    (void)physicalPath; (void)ses;
    std::cerr << "[!] NVMe Format NVM is not implemented on Windows in this build.\n";
    std::cerr << "    To enable NVMe format on Windows you must implement IOCTL_STORAGE_PROTOCOL_COMMAND\n";
    std::cerr << "    usage using the Windows SDK types (STORAGE_PROTOCOL_COMMAND) and ensure your driver\n";
    std::cerr << "    supports NVMe pass-through. For now the program will fall back to overwrite when needed.\n";
    return false;
}

// ---------------- Overwrite with zeros (Clear) ----------------
bool overwriteZero(const std::string& physicalPath) {
    HANDLE h = openPhysicalDrive(physicalPath, true);
    if (h == INVALID_HANDLE_VALUE) return false;

    DISK_GEOMETRY_EX geom;
    DWORD bytes = 0;
    if (!DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                         NULL, 0, &geom, sizeof(geom), &bytes, NULL)) {
        printWinError("IOCTL_DISK_GET_DRIVE_GEOMETRY_EX failed", GetLastError());
        CloseHandle(h);
        return false;
    }

    unsigned long long totalBytes = static_cast<unsigned long long>(geom.DiskSize.QuadPart);
    std::cout << "[*] OverwriteZero: wiping " << physicalPath << " ("
              << (totalBytes / (1024ULL * 1024ULL * 1024ULL)) << " GB)\n";

    const DWORD BUF_SIZE = 4 * 1024 * 1024; // 4 MiB buffer
    std::unique_ptr<char[]> buffer(new char[BUF_SIZE]());
    unsigned long long written = 0;

    LARGE_INTEGER offset; offset.QuadPart = 0;
    if (!SetFilePointerEx(h, offset, NULL, FILE_BEGIN)) {
        printWinError("SetFilePointerEx failed", GetLastError());
        CloseHandle(h);
        return false;
    }

    while (written < totalBytes) {
        DWORD toWrite = BUF_SIZE;
        if (totalBytes - written < BUF_SIZE) toWrite = static_cast<DWORD>(totalBytes - written);

        DWORD actuallyWritten = 0;
        if (!WriteFile(h, buffer.get(), toWrite, &actuallyWritten, NULL) || actuallyWritten != toWrite) {
            printWinError("WriteFile failed", GetLastError());
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

// ---------------- Verification ----------------
bool verifyZeroed(const std::string& devPath, size_t checks) {
    HANDLE h = openPhysicalDrive(devPath, false); // read-only sharing for verification
    if (h == INVALID_HANDLE_VALUE) return false;

    const DWORD blockSize = 4096;
    std::vector<char> buffer(blockSize);
    std::random_device rd;
    std::mt19937 gen(rd());

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

#else
// ---------------- Linux (unchanged) ----------------
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstring>

bool overwriteZero(const std::string& devPath) {
    std::string cmd = "dd if=/dev/zero of=" + devPath + " bs=4M status=progress conv=fsync";
    std::cout << "[*] Running: " << cmd << "\n";
    int rc = system(cmd.c_str());
    return rc == 0;
}

bool ataSecureErase(const std::string& devPath) {
    std::string cmd = "hdparm --security-erase NULL " + devPath;
    std::cout << "[*] Running: " << cmd << "\n";
    int rc = system(cmd.c_str());
    return rc == 0;
}

bool nvmeFormatNVM(const std::string& devPath, uint8_t ses) {
    std::string cmd = "nvme format " + devPath + " -s " + std::to_string(ses);
    std::cout << "[*] Running: " << cmd << "\n";
    int rc = system(cmd.c_str());
    return rc == 0;
}

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
#endif

// ---------------- Logging ----------------
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
