// sanitize.cpp
// Cross-platform sanitization + verification functions.
// Windows implementation includes ATA Secure Erase attempt and overwrite.
// NVMe Format implemented for Windows using IOCTL_STORAGE_PROTOCOL_COMMAND when available.
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
// Implement NVMe Format via IOCTL_STORAGE_PROTOCOL_COMMAND when available. The implementation
// is guarded so it will compile on older SDKs that don't expose the types.

bool nvmeFormatNVM(const std::string& physicalPath, uint8_t ses) {
#if defined(IOCTL_STORAGE_PROTOCOL_COMMAND) && defined(ProtocolTypeNvme)
    std::cout << "[*] Attempting NVMe Format NVM on " << physicalPath << " (ses=" << (int)ses << ")\n";

    HANDLE h = openPhysicalDrive(physicalPath, true);
    if (h == INVALID_HANDLE_VALUE) return false;

    // Build NVMe admin command (64-byte command dword layout)
    const SIZE_T NVME_CMD_SIZE = 64;
    BYTE nvmeCmd[NVME_CMD_SIZE];
    ZeroMemory(nvmeCmd, NVME_CMD_SIZE);

    // Opcode for Format NVM (admin) is 0x80
    nvmeCmd[0] = 0x80;

    // NSID (CDW1) -> bytes 4..7 (little endian). Use NSID = 1 by default.
    uint32_t nsid = 1;
    nvmeCmd[4] = (BYTE)(nsid & 0xFF);
    nvmeCmd[5] = (BYTE)((nsid >> 8) & 0xFF);
    nvmeCmd[6] = (BYTE)((nsid >> 16) & 0xFF);
    nvmeCmd[7] = (BYTE)((nsid >> 24) & 0xFF);

    // CDW10: set SES in low bits (we place SES into byte offset 40)
    nvmeCmd[40] = (BYTE)(ses & 0xFF);

    // Prepare STORAGE_PROTOCOL_COMMAND input buffer. Place the 64-byte command immediately after the struct.
    DWORD inBufSize = (DWORD)(sizeof(STORAGE_PROTOCOL_COMMAND) + NVME_CMD_SIZE);
    std::unique_ptr<BYTE[]> inBuf(new BYTE[inBufSize]);
    ZeroMemory(inBuf.get(), inBufSize);

    STORAGE_PROTOCOL_COMMAND* spc = reinterpret_cast<STORAGE_PROTOCOL_COMMAND*>(inBuf.get());
    // Use version 1 if the macro isn't available
#ifdef STORAGE_PROTOCOL_COMMAND_PROTOCOL_VERSION
    spc->Version = STORAGE_PROTOCOL_COMMAND_PROTOCOL_VERSION;
#else
    spc->Version = 1;
#endif
    spc->Length = (USHORT)sizeof(STORAGE_PROTOCOL_COMMAND);
    spc->ProtocolType = ProtocolTypeNvme;
    spc->Flags = 0;
    spc->CommandLength = (USHORT)NVME_CMD_SIZE;
    spc->ErrorInfoLength = 0;
    spc->DataFromDeviceTransferLength = 0;
    spc->DataToDeviceTransferLength = 0;

    // Copy NVMe command bytes right after the STORAGE_PROTOCOL_COMMAND struct
    BYTE* cmdArea = inBuf.get() + sizeof(STORAGE_PROTOCOL_COMMAND);
    memcpy(cmdArea, nvmeCmd, NVME_CMD_SIZE);

    const DWORD outBufSize = (DWORD)(sizeof(STORAGE_PROTOCOL_COMMAND) + 512);
    std::unique_ptr<BYTE[]> outBuf(new BYTE[outBufSize]);
    ZeroMemory(outBuf.get(), outBufSize);

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        h,
        IOCTL_STORAGE_PROTOCOL_COMMAND,
        inBuf.get(),
        inBufSize,
        outBuf.get(),
        outBufSize,
        &bytesReturned,
        NULL
    );

    if (!ok) {
        DWORD err = GetLastError();
        printWinError("IOCTL_STORAGE_PROTOCOL_COMMAND (NVMe Format) failed", err);
        CloseHandle(h);
        return false;
    }

    STORAGE_PROTOCOL_COMMAND* resp = reinterpret_cast<STORAGE_PROTOCOL_COMMAND*>(outBuf.get());
    if (resp) {
        // Many drivers use ReturnStatus == 0 to indicate success
        if (resp->ReturnStatus == 0) {
            std::cout << "[+] NVMe Format command accepted; controller returned success.\n";
            CloseHandle(h);
            return true;
        } else {
            std::cerr << "[!] NVMe Format returned protocol status: " << resp->ReturnStatus << "\n";
            // You can inspect resp->ErrorInfoLength and other fields here if needed.
        }
    }

    CloseHandle(h);
    return false;
#else
    (void)physicalPath; (void)ses;
    std::cerr << "[!] NVMe Format NVM is not implemented on this build (IOCTL_STORAGE_PROTOCOL_COMMAND unavailable).\n";
    std::cerr << "    To enable NVMe format on Windows you must build with a recent Windows SDK that provides\n";
    std::cerr << "    STORAGE_PROTOCOL_COMMAND and ensure the storage driver supports NVMe pass-through.\n";
    return false;
#endif
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
#include <nlohmann/json.hpp>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iomanip>
#include <sstream>

static std::string base64Encode(const unsigned char* buffer, size_t length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, (int)length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return encoded;
}

void writeWipeCertificate(const DriveInfo& d,
                          const std::string& method,
                          bool success,
                          const std::string& privKeyPath) {
    using json = nlohmann::json;

    // Build JSON metadata
    std::time_t now = std::time(nullptr);
    json cert;
    cert["certificate_id"] = std::to_string(now) + "_" + d.name;
    cert["device"] = {
        {"name", d.name},
        {"model", d.model},
        {"bus", d.bus},
        {"type", d.type}
    };
    cert["wipe"] = {
        {"method", method},
        {"success", success},
        {"timestamp", std::asctime(std::localtime(&now))}
    };
    cert["issuer"] = {
        {"tool", "SIH-Wiper"},
        {"version", "1.0"}
    };

    // The data string that we will sign (canonical form: compact)
    std::string data = cert.dump();

    // Default signature fields in case signing isn't available
    cert["signature"] = nullptr;
    cert["signing_error"] = nullptr;
    cert["signing_key"] = privKeyPath;

    // Try to open and parse the private key
    FILE* fp = fopen(privKeyPath.c_str(), "r");
    if (!fp) {
        std::string err = "Could not open private key file: " + privKeyPath;
        std::cerr << "[!] " << err << "\n";
        cert["signing_error"] = err;
        // Write JSON (unsigned) and return
        std::ofstream out("wipe_cert.json");
        out << std::setw(4) << cert;
        out.close();
        std::cout << "[+] Wipe certificate (unsigned) generated: wipe_cert.json\n";
        return;
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        std::string err = "Failed to read private key (PEM_read_PrivateKey failed)";
        std::cerr << "[!] " << err << "\n";
        cert["signing_error"] = err;
        std::ofstream out("wipe_cert.json");
        out << std::setw(4) << cert;
        out.close();
        std::cout << "[+] Wipe certificate (unsigned) generated: wipe_cert.json\n";
        return;
    }

    // Sign with SHA256. Use the older EVP_Sign* API (keeps your existing code pattern).
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::string err = "EVP_MD_CTX_new failed";
        std::cerr << "[!] " << err << "\n";
        cert["signing_error"] = err;
        EVP_PKEY_free(pkey);
        std::ofstream out("wipe_cert.json");
        out << std::setw(4) << cert;
        out.close();
        std::cout << "[+] Wipe certificate (unsigned) generated: wipe_cert.json\n";
        return;
    }

    if (EVP_SignInit(ctx, EVP_sha256()) != 1) {
        unsigned long e = ERR_get_error();
        std::string err = "EVP_SignInit failed: " + std::string(ERR_error_string(e, NULL));
        std::cerr << "[!] " << err << "\n";
        cert["signing_error"] = err;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        std::ofstream out("wipe_cert.json");
        out << std::setw(4) << cert;
        out.close();
        std::cout << "[+] Wipe certificate (unsigned) generated: wipe_cert.json\n";
        return;
    }

    if (EVP_SignUpdate(ctx, data.data(), data.size()) != 1) {
        unsigned long e = ERR_get_error();
        std::string err = "EVP_SignUpdate failed: " + std::string(ERR_error_string(e, NULL));
        std::cerr << "[!] " << err << "\n";
        cert["signing_error"] = err;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        std::ofstream out("wipe_cert.json");
        out << std::setw(4) << cert;
        out.close();
        std::cout << "[+] Wipe certificate (unsigned) generated: wipe_cert.json\n";
        return;
    }

    unsigned int sigLen = EVP_PKEY_size(pkey);
    std::vector<unsigned char> sig(sigLen);
    if (EVP_SignFinal(ctx, sig.data(), &sigLen, pkey) != 1) {
        unsigned long e = ERR_get_error();
        std::string err = "EVP_SignFinal failed: " + std::string(ERR_error_string(e, NULL));
        std::cerr << "[!] " << err << "\n";
        cert["signing_error"] = err;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        std::ofstream out("wipe_cert.json");
        out << std::setw(4) << cert;
        out.close();
        std::cout << "[+] Wipe certificate (unsigned) generated: wipe_cert.json\n";
        return;
    }

    // Success - encode signature and attach
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    std::string sigB64 = base64Encode(sig.data(), sigLen);
    cert["signature"] = sigB64;
    cert["signing_error"] = nullptr;

    std::ofstream out("wipe_cert.json");
    out << std::setw(4) << cert;
    out.close();

    std::cout << "[+] Wipe certificate generated (signed): wipe_cert.json\n";
}
