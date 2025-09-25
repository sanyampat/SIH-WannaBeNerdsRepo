// windows_sanitize_all.cpp
// Compile with Visual Studio (MSVC). Run as Administrator.
// WARNING: Destructive operations. Test on non-production drives only.

#include <windows.h>
#include <winioctl.h>
#include <ntddscsi.h>      // for ATA_PASS_THROUGH_EX (may require Windows SDK)
#include <iostream>
#include <vector>
#include <string>
#include <memory>

#pragma comment(lib, "Advapi32.lib")

// Helper: open physical drive (e.g. "\\\\.\\PhysicalDrive0")
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

// ---------------------- Overwrite / Write-zero fallback ----------------------
bool overwriteZero(const std::string& physicalPath) {
    HANDLE h = openPhysicalDrive(physicalPath);
    if (h == INVALID_HANDLE_VALUE) return false;

    // Query size
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

    const DWORD BUF_SIZE = 4 * 1024 * 1024; // 4MiB buffer
    std::unique_ptr<char[]> buffer(new char[BUF_SIZE]());
    unsigned long long written = 0;

    LARGE_INTEGER offset;
    offset.QuadPart = 0;
    if (!SetFilePointerEx(h, offset, NULL, FILE_BEGIN)) {
        std::cerr << "[!] SetFilePointerEx failed (err=" << GetLastError() << ")\n";
        CloseHandle(h);
        return false;
    }

    while (written < totalBytes) {
        DWORD toWrite = BUF_SIZE;
        if (totalBytes - written < Buf_SIZE) toWrite = static_cast<DWORD>(totalBytes - written);

        DWORD actuallyWritten = 0;
        if (!WriteFile(h, buffer.get(), toWrite, &actuallyWritten, NULL) || actuallyWritten != toWrite) {
            std::cerr << "[!] WriteFile failed at " << written << " bytes (err=" << GetLastError() << ")\n";
            CloseHandle(h);
            return false;
        }

        written += actuallyWritten;
        // Simple progress print every 1 GB
        if ((written / (1024ULL*1024ULL*1024ULL)) != ((written - actuallyWritten) / (1024ULL*1024ULL*1024ULL))) {
            std::cout << "   -> " << (written / (1024ULL*1024ULL*1024ULL)) << " GB written\n";
        }
    }

    FlushFileBuffers(h);
    CloseHandle(h);
    std::cout << "[+] OverwriteZero: done for " << physicalPath << "\n";
    return true;
}

// ---------------------- ATA Secure Erase (IOCTL_ATA_PASS_THROUGH) ----------------------
// Notes:
//  - Many drives require a user password be set before SECURITY ERASE UNIT will run.
//  - The security set password command (0xF1) must be run prior to 0xF4.
//  - This example attempts to send SECURITY ERASE UNIT (0xF4) with a TEMP password "passwd" (example).
//  - In production you should set/check security state via IDENTIFY DEVICE and follow proper steps.

bool ataSecureErase(const std::string& physicalPath) {
    HANDLE h = openPhysicalDrive(physicalPath);
    if (h == INVALID_HANDLE_VALUE) return false;

    std::cout << "[*] ATA Secure Erase requested for " << physicalPath << "\n";

    // Prepare ATA_PASS_THROUGH_EX buffer.
    // We use ATA_PASS_THROUGH_EX + 512 bytes data buffer (no data for ERASE but some drivers expect buffer).
    const DWORD bufSize = sizeof(ATA_PASS_THROUGH_EX) + 512;
    std::unique_ptr<BYTE[]> buf(new BYTE[bufSize]);
    ZeroMemory(buf.get(), bufSize);

    auto* apt = reinterpret_cast<ATA_PASS_THROUGH_EX*>(buf.get());
    apt->Length = sizeof(ATA_PASS_THROUGH_EX);
    apt->TimeOutValue = 120; // seconds
    apt->DataTransferLength = 0; // no data direction for SECURITY ERASE UNIT itself
    apt->DataBufferOffset = 0;

    // Build task file
    // SECURITY ERASE UNIT = 0xF4
    // PIO data-out not needed for command, but we set registers per ATA spec.
    // CurrentTaskFile: [0]=Feature, [1]=SectorCount, [2]=SectorNumber, [3]=CylinderLow, [4]=CylinderHigh, [5]=DeviceHead, [6]=Command
    // For some drives, you need to set feature with 0x00/0x01 for enhanced.
    apt->CurrentTaskFile[6] = 0xF4; // Command code SECURITY ERASE UNIT

    DWORD returned = 0;
    BOOL ok = DeviceIoControl(
        h,
        IOCTL_ATA_PASS_THROUGH,
        buf.get(), bufSize,
        buf.get(), bufSize,
        &returned,
        NULL
    );

    if (!ok) {
        std::cerr << "[!] IOCTL_ATA_PASS_THROUGH failed (err=" << GetLastError() << ")\n";
    } else {
        std::cout << "[+] IOCTL_ATA_PASS_THROUGH issued (SECURE ERASE). Check drive status to confirm.\n";
    }

    CloseHandle(h);
    return ok != FALSE;
}

// ---------------------- NVMe Format NVM (IOCTL_STORAGE_PROTOCOL_COMMAND) ----------------------
// We'll construct an NVMe admin Format NVM (opcode 0x80) command.
// SES in CDW10 bits[2:0] -> 1 = user data erase, 2 = crypto erase

#pragma pack(push, 1)
struct NVME_COMMAND_64 {
    uint32_t cdw0;
    uint32_t nsid;
    uint64_t resv;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint32_t cdw10;
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
};
#pragma pack(pop)

bool nvmeFormatNVM(const std::string& physicalPath, uint8_t ses = 1) {
    HANDLE h = openPhysicalDrive(physicalPath);
    if (h == INVALID_HANDLE_VALUE) return false;

    std::cout << "[*] NVMe Format NVM requested for " << physicalPath << " (SES=" << (int)ses << ")\n";

    // Prepare STORAGE_PROTOCOL_COMMAND
    // We'll send an NVMe Admin command Format NVM (opcode 0x80)
    STORAGE_PROTOCOL_COMMAND protocolCmd;
    ZeroMemory(&protocolCmd, sizeof(protocolCmd));
    protocolCmd.Length = sizeof(protocolCmd);
    protocolCmd.Version = sizeof(protocolCmd);
    protocolCmd.ProtocolType = ProtocolTypeNvme;
    protocolCmd.Flags = 0;
    protocolCmd.CommandLength = sizeof(NVME_COMMAND_64);
    protocolCmd.ErrorCode = 0;

    // Buffer to hold command
    BYTE commandBuffer[sizeof(NVME_COMMAND_64)];
    ZeroMemory(commandBuffer, sizeof(commandBuffer));
    NVME_COMMAND_64* nvme = reinterpret_cast<NVME_COMMAND_64*>(commandBuffer);

    // cdw0: OPC (bits 7:0)
    nvme->cdw0 = 0x80; // Format NVM opcode (admin)
    // nsid = 0xffffffff for controller (format all namespaces) or specific NSID
    nvme->nsid = 0xffffffff;

    // cdw10 holds SES (bits 2:0) per NVMe spec
    nvme->cdw10 = ses & 0x7;

    // Copy command into protocolCmd.Command
    // STORAGE_PROTOCOL_COMMAND.Command is a flexible array; set CommandOffset and transfer lengths appropriately.
    const DWORD headerSize = sizeof(STORAGE_PROTOCOL_COMMAND);
    const DWORD totalSize = headerSize + sizeof(commandBuffer);

    // Allocate buffer for ioctl
    std::unique_ptr<BYTE[]> ioBuf(new BYTE[totalSize]);
    ZeroMemory(ioBuf.get(), totalSize);

    // Fill STORAGE_PROTOCOL_COMMAND at start
    STORAGE_PROTOCOL_COMMAND* outCmd = reinterpret_cast<STORAGE_PROTOCOL_COMMAND*>(ioBuf.get());
    *outCmd = protocolCmd;

    // Copy raw NVMe command into the command buffer inside the struct:
    // In the STORAGE_PROTOCOL_COMMAND layout, the Command field starts after...
    // To be safe, we place NVMe command at offset sizeof(STORAGE_PROTOCOL_COMMAND)
    memcpy(ioBuf.get() + headerSize, commandBuffer, sizeof(commandBuffer));

    // Set fields that depend on offsets
    outCmd->CommandLength = sizeof(commandBuffer);
    outCmd->CommandOffset = headerSize;
    outCmd->ErrorCode = 0;

    DWORD returned = 0;
    BOOL ok = DeviceIoControl(
        h,
        IOCTL_STORAGE_PROTOCOL_COMMAND,
        ioBuf.get(), totalSize,
        ioBuf.get(), totalSize,
        &returned,
        NULL
    );

    if (!ok) {
        std::cerr << "[!] IOCTL_STORAGE_PROTOCOL_COMMAND failed (err=" << GetLastError() << ")\n";
    } else {
        std::cout << "[+] IOCTL_STORAGE_PROTOCOL_COMMAND sent (Format NVM). Check drive for completion.\n";
    }

    CloseHandle(h);
    return ok != FALSE;
}

// ---------------------- Simple demo main ----------------------
int main() {
    std::cout << "Windows sanitization demo (overwrite, ATA secure erase, NVMe format)\n";
    std::cout << "WARNING: destructive. Run only on test hardware.\n\n";

    // Example device paths - change to match your system:
    // Use \\.\PhysicalDriveN where N is the physical disk number.
    std::vector<std::string> devices = {
        "\\\\.\\PhysicalDrive0",
        // "\\\\.\\PhysicalDrive1",
        // add more as needed
    };

    for (const auto& dev : devices) {
        std::cout << "\n--- Device: " << dev << " ---\n";

        // 1) Overwrite zero (universal fallback)
        if (!overwriteZero(dev)) {
            std::cerr << "   Overwrite failed or aborted for " << dev << "\n";
        }

        // 2) ATA Secure Erase (try - will likely fail on NVMe or if drive not ATA)
        // IMPORTANT: If the device is NVMe, this IOCTL will likely fail. The caller should only call ATA on ATA devices.
        if (!ataSecureErase(dev)) {
            std::cerr << "   ATA Secure Erase returned failure (see message). This may be normal for non-ATA devices.\n";
        }

        // 3) NVMe Format NVM (attempt Format with SES=1)
        if (!nvmeFormatNVM(dev, 1)) {
            std::cerr << "   NVMe Format NVM returned failure (see message). This may be normal for non-NVMe devices.\n";
        }
    }

    std::cout << "\nDone demo.\n";
    return 0;
}
