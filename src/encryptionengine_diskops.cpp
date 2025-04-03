#include "encryptionengine_diskops.h"
#include "encryptionengine.h"
#include "logging/secure_logger.h"
#include <QFile>
#include <QDir>
#include <QStorageInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QDebug>
#include <QRandomGenerator>
#include <QSettings>

// Header format for the encrypted disk
#define DISK_HEADER_MAGIC "OPENCRYPT_DISK_V2"  // Updated version for hidden volume support
#define DISK_HEADER_MAGIC_V1 "OPENCRYPT_DISK_V1"  // Original version for backward compatibility

namespace DiskOperations {

DiskInfoList getAvailableDisks() {
    DiskInfoList diskList;
    
    // Get list of mounted volumes
    QList<QStorageInfo> storages = QStorageInfo::mountedVolumes();
    
#ifdef Q_OS_LINUX
    // On Linux, use lsblk to get additional disk information
    QProcess process;
    process.start("lsblk", QStringList() << "-J" << "-o" << "NAME,SIZE,TYPE,MOUNTPOINT,REMOVABLE,FSTYPE");
    process.waitForFinished();
    QByteArray output = process.readAllStandardOutput();
    
    // Parse JSON output
    QJsonDocument doc = QJsonDocument::fromJson(output);
    if (!doc.isNull() && doc.isObject()) {
        QJsonArray devices = doc.object()["blockdevices"].toArray();
        for (const QJsonValue &device : devices) {
            QJsonObject deviceObj = device.toObject();
            
            // Skip loop devices and CD-ROMs
            QString type = deviceObj["type"].toString();
            if (type == "loop" || type == "rom")
                continue;
                
            // Get device information
            DiskInfo diskInfo;
            diskInfo.name = deviceObj["name"].toString();
            diskInfo.path = "/dev/" + diskInfo.name;
            diskInfo.type = type;
            diskInfo.size = deviceObj["size"].toString().toLongLong();
            diskInfo.isRemovable = deviceObj["rm"].toString() == "1";
            
            // Check if it's a mounted partition
            QString mountpoint = deviceObj["mountpoint"].toString();
            if (!mountpoint.isEmpty() && mountpoint != "[SWAP]") {
                diskInfo.path = mountpoint;
            }
            
            // Check if device is already encrypted (LUKS)
            QString fstype = deviceObj["fstype"].toString();
            diskInfo.isEncrypted = fstype == "crypto_LUKS";
            
            diskList.append(diskInfo);
            
            // Check for partitions
            QJsonArray children = deviceObj["children"].toArray();
            for (const QJsonValue &child : children) {
                QJsonObject childObj = child.toObject();
                
                // Skip swap partitions
                QString childType = childObj["fstype"].toString();
                if (childType == "swap")
                    continue;
                    
                DiskInfo partInfo;
                partInfo.name = childObj["name"].toString();
                partInfo.path = "/dev/" + partInfo.name;
                partInfo.type = "partition";
                partInfo.size = childObj["size"].toString().toLongLong();
                partInfo.isRemovable = diskInfo.isRemovable;
                
                // Check if it's a mounted partition
                QString childMountpoint = childObj["mountpoint"].toString();
                if (!childMountpoint.isEmpty() && childMountpoint != "[SWAP]") {
                    partInfo.path = childMountpoint;
                }
                
                // Check if partition is already encrypted (LUKS)
                QString childFstype = childObj["fstype"].toString();
                partInfo.isEncrypted = childFstype == "crypto_LUKS";
                
                diskList.append(partInfo);
            }
        }
    }
#elif defined(Q_OS_WINDOWS)
    // Windows: Use WMI to get disk info (simplified version)
    QProcess process;
    process.start("wmic", QStringList() << "diskdrive" << "get" << "DeviceID,MediaType,Size,InterfaceType" << "/format:csv");
    process.waitForFinished();
    QByteArray output = process.readAllStandardOutput();
    
    // Simple parsing of the CSV output
    QStringList lines = QString(output).split('\n');
    if (lines.size() > 1) {  // Skip the header line
        for (int i = 1; i < lines.size(); i++) {
            QStringList fields = lines[i].split(',');
            if (fields.size() >= 4) {
                DiskInfo diskInfo;
                diskInfo.path = fields[1]; // DeviceID
                diskInfo.name = diskInfo.path.mid(diskInfo.path.lastIndexOf('\\') + 1);
                diskInfo.type = fields[2]; // MediaType
                diskInfo.size = fields[3].toLongLong(); // Size
                diskInfo.isRemovable = (fields[4] == "USB");  // InterfaceType
                diskInfo.isEncrypted = false; // Cannot easily determine this in Windows
                
                diskList.append(diskInfo);
            }
        }
    }
    
    // Get volumes information
    process.start("wmic", QStringList() << "logicaldisk" << "get" << "DeviceID,DriveType,Size,VolumeName" << "/format:csv");
    process.waitForFinished();
    output = process.readAllStandardOutput();
    
    lines = QString(output).split('\n');
    if (lines.size() > 1) {  // Skip the header line
        for (int i = 1; i < lines.size(); i++) {
            QStringList fields = lines[i].split(',');
            if (fields.size() >= 4) {
                DiskInfo diskInfo;
                diskInfo.path = fields[1]; // DeviceID
                diskInfo.name = fields[4].isEmpty() ? diskInfo.path : fields[4]; // VolumeName
                diskInfo.type = "partition";
                diskInfo.size = fields[3].toLongLong(); // Size
                
                // DriveType: 2=Removable, 3=Fixed, 4=Network, 5=Optical, 6=RAM disk
                int driveType = fields[2].toInt(); 
                diskInfo.isRemovable = (driveType == 2 || driveType == 5 || driveType == 6);
                diskInfo.isEncrypted = false; // Cannot easily determine this in Windows
                
                diskList.append(diskInfo);
            }
        }
    }
#elif defined(Q_OS_MAC)
    // macOS: Use diskutil to get disk info
    QProcess process;
    process.start("diskutil", QStringList() << "list" << "-plist");
    process.waitForFinished();
    QByteArray output = process.readAllStandardOutput();
    
    // Parse plist output using QSettings
    QTemporaryFile tempFile;
    if (tempFile.open()) {
        tempFile.write(output);
        tempFile.close();
        
        QSettings plist(tempFile.fileName(), QSettings::NativeFormat);
        int diskCount = plist.beginReadArray("AllDisksAndPartitions");
        
        for (int i = 0; i < diskCount; i++) {
            plist.setArrayIndex(i);
            
            DiskInfo diskInfo;
            diskInfo.name = plist.value("DeviceIdentifier").toString();
            diskInfo.path = "/dev/" + diskInfo.name;
            diskInfo.size = plist.value("Size").toLongLong();
            
            // Get media type
            QProcess detailProcess;
            detailProcess.start("diskutil", QStringList() << "info" << "-plist" << diskInfo.path);
            detailProcess.waitForFinished();
            
            QTemporaryFile detailTempFile;
            if (detailTempFile.open()) {
                detailTempFile.write(detailProcess.readAllStandardOutput());
                detailTempFile.close();
                
                QSettings detailPlist(detailTempFile.fileName(), QSettings::NativeFormat);
                diskInfo.type = detailPlist.value("MediaType").toString();
                diskInfo.isRemovable = detailPlist.value("Removable").toBool();
                diskInfo.isEncrypted = detailPlist.value("Encrypted").toBool();
            }
            
            diskList.append(diskInfo);
            
            // Get partitions
            int partCount = plist.beginReadArray("Partitions");
            for (int j = 0; j < partCount; j++) {
                plist.setArrayIndex(j);
                
                DiskInfo partInfo;
                partInfo.name = plist.value("DeviceIdentifier").toString();
                partInfo.path = "/dev/" + partInfo.name;
                partInfo.type = "partition";
                partInfo.size = plist.value("Size").toLongLong();
                partInfo.isRemovable = diskInfo.isRemovable;
                
                // Get partition details
                QProcess partDetailProcess;
                partDetailProcess.start("diskutil", QStringList() << "info" << "-plist" << partInfo.path);
                partDetailProcess.waitForFinished();
                
                QTemporaryFile partDetailTempFile;
                if (partDetailTempFile.open()) {
                    partDetailTempFile.write(partDetailProcess.readAllStandardOutput());
                    partDetailTempFile.close();
                    
                    QSettings partDetailPlist(partDetailTempFile.fileName(), QSettings::NativeFormat);
                    partInfo.isEncrypted = partDetailPlist.value("Encrypted").toBool();
                    
                    // If mounted, use the mount point as path
                    if (partDetailPlist.value("Mounted").toBool()) {
                        partInfo.path = partDetailPlist.value("MountPoint").toString();
                    }
                }
                
                diskList.append(partInfo);
            }
            plist.endArray(); // Partitions
        }
        plist.endArray(); // AllDisksAndPartitions
    }
#endif

    // Also add all mounted volumes from QStorageInfo if not already in the list
    for (const QStorageInfo &storage : storages) {
        bool found = false;
        for (const DiskInfo &disk : diskList) {
            if (disk.path == storage.rootPath()) {
                found = true;
                break;
            }
        }
        
        if (!found && storage.isValid() && !storage.isReadOnly()) {
            DiskInfo diskInfo;
            diskInfo.path = storage.rootPath();
            diskInfo.name = storage.displayName();
            if (diskInfo.name.isEmpty()) {
                diskInfo.name = storage.rootPath();
            }
            diskInfo.type = "volume";
            diskInfo.size = storage.bytesTotal();
            diskInfo.isRemovable = false; // Cannot easily determine this
            diskInfo.isEncrypted = false; // Cannot easily determine this
            
            diskList.append(diskInfo);
        }
    }
    
    return diskList;
}

bool isValidDiskPath(const QString& path) {
    // First, check if the path exists
    QFileInfo fileInfo(path);
    if (!fileInfo.exists()) {
        SECURE_LOG(ERROR, "DiskOperations", QString("Path does not exist: %1").arg(path));
        return false;
    }
    
    // Make sure the path is writable
    if (!fileInfo.isWritable()) {
        SECURE_LOG(ERROR, "DiskOperations", QString("Path is not writable: %1").arg(path));
        return false;
    }
    
#ifdef Q_OS_LINUX
    // On Linux, check if the path is a block device or a mounted directory
    if (path.startsWith("/dev/")) {
        // It's a block device, make sure we have permission to write to it
        QFile device(path);
        if (!device.open(QIODevice::ReadWrite)) {
            SECURE_LOG(ERROR, "DiskOperations", QString("Cannot open device for writing: %1").arg(path));
            return false;
        }
        device.close();
        return true;
    } else {
        // It's a directory, make sure it's mounted and not the root directory
        QStorageInfo storage(path);
        if (!storage.isValid() || !storage.isReady() || storage.isRoot()) {
            SECURE_LOG(ERROR, "DiskOperations", QString("Invalid storage location or root directory: %1").arg(path));
            return false;
        }
        return true;
    }
#elif defined(Q_OS_WINDOWS)
    // On Windows, check if the path is a volume (like C:\)
    if (path.length() == 3 && path.at(1) == ':' && path.at(2) == '\\') {
        // It's a drive letter, make sure it's not the system drive
        QProcess process;
        process.start("wmic", QStringList() << "logicaldisk" << "where" << "DeviceID='" + path.left(2) + "'" << "get" << "DriveType");
        process.waitForFinished();
        QString output = process.readAllStandardOutput();
        
        // DriveType: 2=Removable, 3=Fixed, 4=Network, 5=Optical, 6=RAM disk
        // Only allow removable drives (2), network drives (4), or RAM disks (6)
        int driveType = output.trimmed().split("\n").last().trimmed().toInt();
        if (driveType == 3) {
            // It's a fixed drive, make sure it's not the system drive
            process.start("wmic", QStringList() << "OS" << "get" << "SystemDrive");
            process.waitForFinished();
            QString systemDrive = process.readAllStandardOutput().trimmed().split("\n").last().trimmed();
            
            if (systemDrive.compare(path.left(2), Qt::CaseInsensitive) == 0) {
                SECURE_LOG(ERROR, "DiskOperations", QString("Cannot encrypt system drive: %1").arg(path));
                return false;
            }
        }
        
        // For physical drives (\\.\PhysicalDriveX)
        if (path.startsWith("\\\\.\\")) {
            QFile device(path);
            if (!device.open(QIODevice::ReadWrite)) {
                SECURE_LOG(ERROR, "DiskOperations", QString("Cannot open device for writing: %1").arg(path));
                return false;
            }
            device.close();
        }
        
        return true;
    } else {
        // It's a directory, make sure it exists and is writable
        QDir dir(path);
        if (!dir.exists()) {
            SECURE_LOG(ERROR, "DiskOperations", QString("Directory does not exist: %1").arg(path));
            return false;
        }
        
        // Create a temp file to check if we can write to the directory
        QTemporaryFile tempFile(path + "/opencrypttest_XXXXXX");
        if (!tempFile.open()) {
            SECURE_LOG(ERROR, "DiskOperations", QString("Cannot write to directory: %1").arg(path));
            return false;
        }
        
        return true;
    }
#elif defined(Q_OS_MAC)
    // On macOS, check if the path is a disk device or a mounted directory
    if (path.startsWith("/dev/")) {
        // It's a disk device, check if we can open it for writing
        QFile device(path);
        if (!device.open(QIODevice::ReadWrite)) {
            SECURE_LOG(ERROR, "DiskOperations", QString("Cannot open device for writing: %1").arg(path));
            return false;
        }
        device.close();
        
        // Make sure it's not the boot volume
        QProcess process;
        process.start("diskutil", QStringList() << "info" << "-plist" << path);
        process.waitForFinished();
        QString output = process.readAllStandardOutput();
        
        QTemporaryFile tempFile;
        if (tempFile.open()) {
            tempFile.write(output.toUtf8());
            tempFile.close();
            
            QSettings plist(tempFile.fileName(), QSettings::NativeFormat);
            bool isBootVolume = plist.value("SystemImage").toBool();
            
            if (isBootVolume) {
                SECURE_LOG(ERROR, "DiskOperations", QString("Cannot encrypt boot volume: %1").arg(path));
                return false;
            }
        }
        
        return true;
    } else {
        // It's a directory, make sure it's mounted and not the root directory
        QStorageInfo storage(path);
        if (!storage.isValid() || !storage.isReady() || storage.isRoot()) {
            SECURE_LOG(ERROR, "DiskOperations", QString("Invalid storage location or root directory: %1").arg(path));
            return false;
        }
        
        // Create a temp file to check if we can write to the directory
        QTemporaryFile tempFile(path + "/opencrypttest_XXXXXX");
        if (!tempFile.open()) {
            SECURE_LOG(ERROR, "DiskOperations", QString("Cannot write to directory: %1").arg(path));
            return false;
        }
        
        return true;
    }
#else
    // Generic implementation for other platforms
    // Check if it's a directory and we can write to it
    QDir dir(path);
    if (dir.exists()) {
        QTemporaryFile tempFile(path + "/opencrypttest_XXXXXX");
        if (!tempFile.open()) {
            SECURE_LOG(ERROR, "DiskOperations", QString("Cannot write to directory: %1").arg(path));
            return false;
        }
        return true;
    }
    
    // Otherwise, it might be a device file - try to open it
    QFile device(path);
    if (!device.open(QIODevice::ReadWrite)) {
        SECURE_LOG(ERROR, "DiskOperations", QString("Cannot open device for writing: %1").arg(path));
        return false;
    }
    device.close();
    
    return true;
#endif
}

bool createEncryptionHeader(const QString& diskPath, const QString& algorithm, 
                           const QString& kdf, int iterations, bool useHMAC,
                           const QByteArray& salt, const QByteArray& iv,
                           bool hasHiddenVolume) {
    // Prepare the header data as JSON
    QJsonObject headerObj;
    headerObj["magic"] = DISK_HEADER_MAGIC;
    headerObj["algorithm"] = algorithm;
    headerObj["kdf"] = kdf;
    headerObj["iterations"] = iterations;
    headerObj["hmac"] = useHMAC;
    headerObj["salt"] = QString(salt.toBase64());
    headerObj["iv"] = QString(iv.toBase64());
    headerObj["version"] = DISK_HEADER_VERSION;
    headerObj["hasHiddenVolume"] = hasHiddenVolume;
    
    QJsonDocument headerDoc(headerObj);
    QByteArray headerData = headerDoc.toJson();
    
    // Pad the header to 4KB
    headerData.append(QByteArray(DISK_HEADER_SIZE - headerData.size(), 0));
    
    // Write the header to the disk/volume
    QFile diskFile(diskPath);
    if (!diskFile.open(QIODevice::ReadWrite)) {
        SECURE_LOG(ERROR, "DiskOperations", QString("Failed to open disk for writing header: %1").arg(diskPath));
        return false;
    }
    
    // Write the header at the beginning of the disk
    qint64 bytesWritten = diskFile.write(headerData);
    diskFile.close();
    
    if (bytesWritten != DISK_HEADER_SIZE) {
        SECURE_LOG(ERROR, "DiskOperations", QString("Failed to write complete header to disk: %1").arg(diskPath));
        return false;
    }
    
    return true;
}

bool readEncryptionHeader(const QString& diskPath, QString& algorithm, 
                         QString& kdf, int& iterations, bool& useHMAC,
                         QByteArray& salt, QByteArray& iv,
                         bool& hasHiddenVolume) {
    // Read the header from the disk/volume
    QFile diskFile(diskPath);
    if (!diskFile.open(QIODevice::ReadOnly)) {
        SECURE_LOG(ERROR, "DiskOperations", QString("Failed to open disk for reading header: %1").arg(diskPath));
        return false;
    }
    
    // Read the first 4KB for the header
    QByteArray headerData = diskFile.read(DISK_HEADER_SIZE);
    diskFile.close();
    
    if (headerData.size() != DISK_HEADER_SIZE) {
        SECURE_LOG(ERROR, "DiskOperations", QString("Failed to read complete header from disk: %1").arg(diskPath));
        return false;
    }
    
    // Parse the JSON header
    QJsonDocument headerDoc = QJsonDocument::fromJson(headerData);
    if (headerDoc.isNull() || !headerDoc.isObject()) {
        SECURE_LOG(ERROR, "DiskOperations", QString("Invalid header format on disk: %1").arg(diskPath));
        return false;
    }
    
    QJsonObject headerObj = headerDoc.object();
    
    // Verify the magic string (support both formats for backward compatibility)
    QString magic = headerObj["magic"].toString();
    if (magic != DISK_HEADER_MAGIC && magic != DISK_HEADER_MAGIC_V1) {
        SECURE_LOG(ERROR, "DiskOperations", QString("Invalid magic number in header on disk: %1").arg(diskPath));
        return false;
    }
    
    // Extract the encryption parameters
    algorithm = headerObj["algorithm"].toString();
    kdf = headerObj["kdf"].toString();
    iterations = headerObj["iterations"].toInt();
    useHMAC = headerObj["hmac"].toBool();
    salt = QByteArray::fromBase64(headerObj["salt"].toString().toLatin1());
    iv = QByteArray::fromBase64(headerObj["iv"].toString().toLatin1());
    
    // Check for hidden volume (only in V2 format)
    hasHiddenVolume = false;
    if (magic == DISK_HEADER_MAGIC) {
        int version = headerObj["version"].toInt();
        if (version >= DISK_HEADER_VERSION) {
            hasHiddenVolume = headerObj["hasHiddenVolume"].toBool();
        }
    }
    
    return true;
}

bool createHiddenVolume(const QString& diskPath, qint64 hiddenVolumeSize,
                      const QString& algorithm, const QString& kdf,
                      int iterations, bool useHMAC,
                      const QByteArray& salt, const QByteArray& iv) {
    
    // First verify the disk is already encrypted with a main volume
    bool hasHiddenVol = false;
    QString mainAlgorithm, mainKdf;
    int mainIterations;
    bool mainUseHMAC;
    QByteArray mainSalt, mainIv;
    
    if (!readEncryptionHeader(diskPath, mainAlgorithm, mainKdf, mainIterations, 
                             mainUseHMAC, mainSalt, mainIv, hasHiddenVol)) {
        SECURE_LOG(ERROR, "DiskOperations", QString("Failed to read main volume header: %1").arg(diskPath));
        return false;
    }
    
    // Make sure we don't already have a hidden volume
    if (hasHiddenVol) {
        SECURE_LOG(ERROR, "DiskOperations", QString("Disk already has a hidden volume: %1").arg(diskPath));
        return false;
    }
    
    // Calculate the offset for the hidden volume (after the standard header)
    qint64 hiddenVolumeOffset = DISK_HIDDEN_HEADER_OFFSET;
    
    // Prepare the hidden volume header as JSON
    QJsonObject hiddenHeaderObj;
    hiddenHeaderObj["magic"] = DISK_HEADER_MAGIC;
    hiddenHeaderObj["type"] = "hidden";
    hiddenHeaderObj["algorithm"] = algorithm;
    hiddenHeaderObj["kdf"] = kdf;
    hiddenHeaderObj["iterations"] = iterations;
    hiddenHeaderObj["hmac"] = useHMAC;
    hiddenHeaderObj["salt"] = QString(salt.toBase64());
    hiddenHeaderObj["iv"] = QString(iv.toBase64());
    hiddenHeaderObj["offset"] = hiddenVolumeOffset + DISK_HEADER_SIZE;  // Start of actual hidden data
    hiddenHeaderObj["size"] = hiddenVolumeSize;
    hiddenHeaderObj["version"] = DISK_HEADER_VERSION;
    
    QJsonDocument hiddenHeaderDoc(hiddenHeaderObj);
    QByteArray hiddenHeaderData = hiddenHeaderDoc.toJson();
    
    // Pad the header to 4KB
    hiddenHeaderData.append(QByteArray(DISK_HEADER_SIZE - hiddenHeaderData.size(), 0));
    
    // Open the disk file for writing
    QFile diskFile(diskPath);
    if (!diskFile.open(QIODevice::ReadWrite)) {
        SECURE_LOG(ERROR, "DiskOperations", QString("Failed to open disk for writing hidden volume: %1").arg(diskPath));
        return false;
    }
    
    // Seek to the hidden volume header position
    if (!diskFile.seek(hiddenVolumeOffset)) {
        SECURE_LOG(ERROR, "DiskOperations", QString("Failed to seek to hidden volume position: %1").arg(diskPath));
        diskFile.close();
        return false;
    }
    
    // Write the hidden volume header
    qint64 bytesWritten = diskFile.write(hiddenHeaderData);
    
    // Update main volume header to indicate it has a hidden volume
    diskFile.seek(0);
    
    // Read the main header
    QByteArray mainHeaderData = diskFile.read(DISK_HEADER_SIZE);
    QJsonDocument mainHeaderDoc = QJsonDocument::fromJson(mainHeaderData);
    QJsonObject mainHeaderObj = mainHeaderDoc.object();
    
    // Update the main header
    mainHeaderObj["hasHiddenVolume"] = true;
    mainHeaderObj["version"] = DISK_HEADER_VERSION;
    mainHeaderObj["magic"] = DISK_HEADER_MAGIC;
    
    // Write back the updated main header
    QJsonDocument updatedMainDoc(mainHeaderObj);
    QByteArray updatedMainData = updatedMainDoc.toJson();
    updatedMainData.append(QByteArray(DISK_HEADER_SIZE - updatedMainData.size(), 0));
    
    diskFile.seek(0);
    diskFile.write(updatedMainData);
    
    diskFile.close();
    
    if (bytesWritten != DISK_HEADER_SIZE) {
        SECURE_LOG(ERROR, "DiskOperations", QString("Failed to write complete hidden volume header: %1").arg(diskPath));
        return false;
    }
    
    return true;
}

bool readHiddenVolumeHeader(const QString& diskPath, HiddenVolumeInfo& hiddenInfo) {
    // Read the header from the disk/volume
    QFile diskFile(diskPath);
    if (!diskFile.open(QIODevice::ReadOnly)) {
        SECURE_LOG(ERROR, "DiskOperations", QString("Failed to open disk for reading hidden header: %1").arg(diskPath));
        return false;
    }
    
    // First check if the main volume has a hidden volume
    diskFile.seek(0);
    QByteArray mainHeaderData = diskFile.read(DISK_HEADER_SIZE);
    QJsonDocument mainHeaderDoc = QJsonDocument::fromJson(mainHeaderData);
    
    if (mainHeaderDoc.isNull() || !mainHeaderDoc.isObject()) {
        SECURE_LOG(ERROR, "DiskOperations", QString("Invalid main header format on disk: %1").arg(diskPath));
        diskFile.close();
        return false;
    }
    
    QJsonObject mainHeaderObj = mainHeaderDoc.object();
    
    // Check if this volume has a hidden volume
    if (!mainHeaderObj.contains("hasHiddenVolume") || !mainHeaderObj["hasHiddenVolume"].toBool()) {
        SECURE_LOG(ERROR, "DiskOperations", QString("No hidden volume on disk: %1").arg(diskPath));
        diskFile.close();
        return false;
    }
    
    // Seek to the hidden volume header
    diskFile.seek(DISK_HIDDEN_HEADER_OFFSET);
    
    // Read the hidden volume header
    QByteArray hiddenHeaderData = diskFile.read(DISK_HEADER_SIZE);
    diskFile.close();
    
    if (hiddenHeaderData.size() != DISK_HEADER_SIZE) {
        SECURE_LOG(ERROR, "DiskOperations", QString("Failed to read complete hidden header from disk: %1").arg(diskPath));
        return false;
    }
    
    // Parse the JSON header
    QJsonDocument hiddenHeaderDoc = QJsonDocument::fromJson(hiddenHeaderData);
    if (hiddenHeaderDoc.isNull() || !hiddenHeaderDoc.isObject()) {
        SECURE_LOG(ERROR, "DiskOperations", QString("Invalid hidden header format on disk: %1").arg(diskPath));
        return false;
    }
    
    QJsonObject hiddenHeaderObj = hiddenHeaderDoc.object();
    
    // Verify the magic string and type
    if (hiddenHeaderObj["magic"].toString() != DISK_HEADER_MAGIC || 
        hiddenHeaderObj["type"].toString() != "hidden") {
        SECURE_LOG(ERROR, "DiskOperations", QString("Invalid hidden volume header: %1").arg(diskPath));
        return false;
    }
    
    // Extract the hidden volume information
    hiddenInfo.offset = hiddenHeaderObj["offset"].toVariant().toLongLong();
    hiddenInfo.size = hiddenHeaderObj["size"].toVariant().toLongLong();
    hiddenInfo.algorithm = hiddenHeaderObj["algorithm"].toString();
    hiddenInfo.kdf = hiddenHeaderObj["kdf"].toString();
    hiddenInfo.iterations = hiddenHeaderObj["iterations"].toInt();
    hiddenInfo.useHMAC = hiddenHeaderObj["hmac"].toBool();
    hiddenInfo.salt = QByteArray::fromBase64(hiddenHeaderObj["salt"].toString().toLatin1());
    hiddenInfo.iv = QByteArray::fromBase64(hiddenHeaderObj["iv"].toString().toLatin1());
    
    return true;
}

bool hasHiddenVolume(const QString& diskPath) {
    // Read the header from the disk/volume
    QFile diskFile(diskPath);
    if (!diskFile.open(QIODevice::ReadOnly)) {
        SECURE_LOG(ERROR, "DiskOperations", QString("Failed to open disk for checking hidden volume: %1").arg(diskPath));
        return false;
    }
    
    // Read the first 4KB for the header
    QByteArray headerData = diskFile.read(DISK_HEADER_SIZE);
    diskFile.close();
    
    if (headerData.size() != DISK_HEADER_SIZE) {
        SECURE_LOG(ERROR, "DiskOperations", QString("Failed to read complete header for checking hidden volume: %1").arg(diskPath));
        return false;
    }
    
    // Parse the JSON header
    QJsonDocument headerDoc = QJsonDocument::fromJson(headerData);
    if (headerDoc.isNull() || !headerDoc.isObject()) {
        SECURE_LOG(ERROR, "DiskOperations", QString("Invalid header format for checking hidden volume: %1").arg(diskPath));
        return false;
    }
    
    QJsonObject headerObj = headerDoc.object();
    
    // Check if this volume has a hidden volume
    if (headerObj.contains("hasHiddenVolume") && headerObj["hasHiddenVolume"].toBool()) {
        return true;
    }
    
    return false;
}

int getDiskSectorSize(const QString& diskPath) {
    // Default sector size (512 bytes is common)
    int sectorSize = 512;
    
#ifdef Q_OS_LINUX
    // On Linux, use IOCTL to get the sector size
    if (diskPath.startsWith("/dev/")) {
        QFile device(diskPath);
        if (device.open(QIODevice::ReadOnly)) {
            // Use BLKSSZGET ioctl to get sector size
            int fd = device.handle();
            QProcess process;
            process.start("blockdev", QStringList() << "--getss" << diskPath);
            process.waitForFinished();
            QString output = process.readAllStandardOutput().trimmed();
            sectorSize = output.toInt();
            device.close();
        }
    }
#elif defined(Q_OS_WINDOWS)
    // On Windows, use DeviceIoControl for physical devices
    if (diskPath.startsWith("\\\\.\\")) {
        // For Windows, this is more complex and would require native API calls
        // Simplified for this example
        sectorSize = 512; // Assume 512 bytes for now
    }
#elif defined(Q_OS_MAC)
    // On macOS, use diskutil to get sector size
    if (diskPath.startsWith("/dev/")) {
        QProcess process;
        process.start("diskutil", QStringList() << "info" << "-plist" << diskPath);
        process.waitForFinished();
        QString output = process.readAllStandardOutput();
        
        QTemporaryFile tempFile;
        if (tempFile.open()) {
            tempFile.write(output.toUtf8());
            tempFile.close();
            
            QSettings plist(tempFile.fileName(), QSettings::NativeFormat);
            sectorSize = plist.value("DeviceBlockSize").toInt();
        }
    }
#endif
    
    // If we couldn't get the sector size, use a safe default
    if (sectorSize <= 0) {
        sectorSize = 512;
    }
    
    return sectorSize;
}

qint64 calculateEncryptableSectors(const QString& diskPath) {
    // Get disk size and sector size
    qint64 diskSize = 0;
    int sectorSize = getDiskSectorSize(diskPath);
    
    // Check if the path is a device or a directory
    if (diskPath.startsWith("/dev/") || diskPath.startsWith("\\\\.\\")) {
        // It's a device, get its size
        QFile device(diskPath);
        if (device.open(QIODevice::ReadOnly)) {
            diskSize = device.size();
            device.close();
        }
    } else {
        // It's a directory, get the free space
        QStorageInfo storage(diskPath);
        if (storage.isValid()) {
            diskSize = storage.bytesAvailable();
        }
    }
    
    // Reserve space for the standard header and potential hidden volume header
    qint64 reservedBytes = DISK_HIDDEN_HEADER_OFFSET + DISK_HEADER_SIZE;
    
    // Calculate the usable space
    qint64 usableBytes = diskSize - reservedBytes;
    
    // Convert to sectors
    qint64 sectors = usableBytes / sectorSize;
    
    return sectors;
}

qint64 calculateHiddenVolumeSize(const QString& diskPath, int percentage) {
    // Get disk size
    qint64 diskSize = 0;
    
    // Check if the path is a device or a directory
    if (diskPath.startsWith("/dev/") || diskPath.startsWith("\\\\.\\")) {
        // It's a device, get its size
        QFile device(diskPath);
        if (device.open(QIODevice::ReadOnly)) {
            diskSize = device.size();
            device.close();
        }
    } else {
        // It's a directory, get the free space
        QStorageInfo storage(diskPath);
        if (storage.isValid()) {
            diskSize = storage.bytesAvailable();
        }
    }
    
    // Make sure the percentage is within bounds
    if (percentage < 10) percentage = 10;
    if (percentage > 80) percentage = 80;
    
    // Reserve space for headers
    qint64 reservedBytes = DISK_HIDDEN_HEADER_OFFSET + DISK_HEADER_SIZE;
    qint64 usableBytes = diskSize - reservedBytes;
    
    // Calculate hidden volume size based on percentage
    qint64 hiddenVolumeSize = usableBytes * percentage / 100;
    
    return hiddenVolumeSize;
}

QString formatDiskSize(qint64 size) {
    constexpr qint64 KB = 1024;
    constexpr qint64 MB = KB * 1024;
    constexpr qint64 GB = MB * 1024;
    constexpr qint64 TB = GB * 1024;
    
    if (size >= TB) {
        return QString("%1 TB").arg(static_cast<double>(size) / TB, 0, 'f', 2);
    } else if (size >= GB) {
        return QString("%1 GB").arg(static_cast<double>(size) / GB, 0, 'f', 2);
    } else if (size >= MB) {
        return QString("%1 MB").arg(static_cast<double>(size) / MB, 0, 'f', 1);
    } else if (size >= KB) {
        return QString("%1 KB").arg(static_cast<double>(size) / KB, 0, 'f', 0);
    } else {
        return QString("%1 bytes").arg(size);
    }
}

QString getDiskDetails(const DiskInfo& diskInfo) {
    QString details;
    
    // Type and name
    details += QString("<b>%1: %2</b><br/>").arg(
        diskInfo.type.isEmpty() ? "Volume" : diskInfo.type.at(0).toUpper() + diskInfo.type.mid(1),
        diskInfo.name
    );
    
    // Path
    details += QString("Path: %1<br/>").arg(diskInfo.path);
    
    // Size
    details += QString("Size: %1<br/>").arg(formatDiskSize(diskInfo.size));
    
    // Removable status
    details += QString("Removable: %1<br/>").arg(diskInfo.isRemovable ? "Yes" : "No");
    
    // Encryption status
    details += QString("Encrypted: %1<br/>").arg(diskInfo.isEncrypted ? "Yes" : "No");
    
    // Hidden volume status
    if (diskInfo.isEncrypted) {
        details += QString("Hidden Volume: %1<br/>").arg(diskInfo.hasHiddenVolume ? "Yes" : "No");
    }
    
    return details;
}

} // namespace DiskOperations