#ifndef ENCRYPTIONENGINE_DISKOPS_H
#define ENCRYPTIONENGINE_DISKOPS_H

#include <QString>
#include <QStringList>
#include <QFile>
#include <QDir>
#include <QTemporaryFile>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>
#include "encryptionengine.h"

class EncryptionEngine;

// Define the disk header sizes
#define DISK_HEADER_SIZE 4096  // 4KB header size for standard volumes
#define DISK_HIDDEN_HEADER_OFFSET 8192  // 8KB offset for hidden volume header

// Define the disk header format version
#define DISK_HEADER_VERSION 2  // Updated version for hidden volume support

/**
 * This file contains the disk encryption operations for EncryptionEngine class
 */

class DiskInfo {
public:
    QString path;
    QString name;
    QString type;  // "usb", "hdd", "ssd", "partition"
    qint64 size;
    bool isRemovable;
    bool isEncrypted;
    bool hasHiddenVolume;  // Whether this disk has a hidden volume
    
    DiskInfo() : size(0), isRemovable(false), isEncrypted(false), hasHiddenVolume(false) {}
};

typedef QList<DiskInfo> DiskInfoList;

// Hidden volume structure to store the information about a hidden volume
struct HiddenVolumeInfo {
    qint64 offset;        // Offset within the main volume where hidden volume starts
    qint64 size;          // Size of the hidden volume in bytes
    QString algorithm;    // Encryption algorithm for the hidden volume
    QString kdf;          // KDF for the hidden volume
    int iterations;       // KDF iterations for the hidden volume
    bool useHMAC;         // Whether HMAC is used for the hidden volume
    QByteArray salt;      // Salt used for key derivation
    QByteArray iv;        // Initialization vector
};

namespace DiskOperations {
    // Get list of available disks/volumes
    DiskInfoList getAvailableDisks();
    
    // Check if the specified path is a valid disk/volume for encryption
    bool isValidDiskPath(const QString& path);
    
    // Create a header file on disk with encryption parameters
    bool createEncryptionHeader(const QString& diskPath, const QString& algorithm, 
                              const QString& kdf, int iterations, bool useHMAC,
                              const QByteArray& salt, const QByteArray& iv,
                              bool hasHiddenVolume = false);
    
    // Read encryption header from an encrypted disk
    bool readEncryptionHeader(const QString& diskPath, QString& algorithm, 
                            QString& kdf, int& iterations, bool& useHMAC,
                            QByteArray& salt, QByteArray& iv,
                            bool& hasHiddenVolume);
    
    // Create a hidden volume within an encrypted disk
    bool createHiddenVolume(const QString& diskPath, qint64 hiddenVolumeSize,
                          const QString& algorithm, const QString& kdf,
                          int iterations, bool useHMAC,
                          const QByteArray& salt, const QByteArray& iv);
    
    // Read hidden volume header from an encrypted disk
    bool readHiddenVolumeHeader(const QString& diskPath, HiddenVolumeInfo& hiddenInfo);
    
    // Detect if a disk has a hidden volume
    bool hasHiddenVolume(const QString& diskPath);
    
    // Get sector size for a disk
    int getDiskSectorSize(const QString& diskPath);
    
    // Calculate how many sectors to encrypt (adjusting for header and metadata)
    qint64 calculateEncryptableSectors(const QString& diskPath);
    
    // Calculate available size for hidden volume (percentage of main volume)
    qint64 calculateHiddenVolumeSize(const QString& diskPath, int percentage);
    
    // Format a disk size to a human-readable string (e.g., "1.5 GB")
    QString formatDiskSize(qint64 size);
    
    // Get detailed information about a disk
    QString getDiskDetails(const DiskInfo& diskInfo);
}

#endif // ENCRYPTIONENGINE_DISKOPS_H