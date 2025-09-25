#pragma once
// sanitize.h
// Declarations for drive sanitization functions.
// WARNING: Implementations may perform destructive operations.

#include <string>
#include <cstdint>

// Shared struct available to all .cpp files
struct DriveInfo {
    std::string name;   // Windows: "C:", Linux: "/dev/sda"
    std::string type;   // HDD, SATA SSD, NVMe SSD, USB, etc.
    std::string model;  // Vendor/model if available
    std::string bus;    // sata, nvme, usb, etc.
};

// Sanitization functions
bool overwriteZero(const std::string& devPath);
bool ataSecureErase(const std::string& devPath);
bool nvmeFormatNVM(const std::string& devPath, uint8_t ses);

// Verification + Logging
bool verifyZeroed(const std::string& devPath, size_t checks = 5);
void logSanitization(const DriveInfo& d, const std::string& method, bool success);

#ifdef _WIN32
// Make the dismount helper visible to other .cpp files (SanitizeDrives.cpp)
bool dismountVolume(const std::string& volPath);
#endif
