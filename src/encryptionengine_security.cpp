#include "encryptionengine.h"
#include "logging/secure_logger.h"
#include <QFileInfo>
#include <QDir>
#include <QStandardPaths>

// Verify that the output path is secure (not in a world-writable directory, etc.)
bool EncryptionEngine::verifyOutputPathSecurity(const QString& filePath)
{
    // Check if the file exists already
    QFileInfo fileInfo(filePath);
    QDir parentDir = fileInfo.dir();
    QString parentPath = parentDir.absolutePath();
    
    // Check if parent directory exists
    if (!parentDir.exists()) {
        SECURE_LOG(ERROR, "EncryptionEngine", 
            QString("Parent directory does not exist: %1").arg(parentPath));
        return false;
    }
    
    // Check if the parent directory permissions are secure
    QFileInfo dirInfo(parentPath);
    QFileDevice::Permissions perms = dirInfo.permissions();
    
    // Check if directory is world-writable
    if (perms & QFileDevice::WriteOther) {
        SECURE_LOG(WARNING, "EncryptionEngine", 
            QString("Security risk: Output directory is world-writable: %1").arg(parentPath));
        
        // Attempt to fix permissions automatically
        if (!checkAndFixFilePermissions(parentPath, 
              QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner | 
              QFileDevice::ReadGroup | QFileDevice::ExeGroup)) {
            
            SECURE_LOG(ERROR, "EncryptionEngine", 
                QString("Could not fix world-writable permissions on: %1").arg(parentPath));
            return false;
        }
    }
    
    // If file exists, check its permissions
    if (fileInfo.exists()) {
        perms = fileInfo.permissions();
        
        // Check if file has unsafe permissions
        if (perms & QFileDevice::ReadOther || perms & QFileDevice::WriteOther) {
            SECURE_LOG(WARNING, "EncryptionEngine", 
                QString("Security risk: Output file has insecure permissions: %1").arg(filePath));
            
            // Attempt to fix permissions automatically
            if (!checkAndFixFilePermissions(filePath, 
                  QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
                
                SECURE_LOG(ERROR, "EncryptionEngine", 
                    QString("Could not fix insecure permissions on: %1").arg(filePath));
                return false;
            }
        }
    }
    
    // Check if path is in a dangerous location
    QStringList dangerousPaths = {
        "/tmp", "/var/tmp", "/dev/shm", "/proc", "/sys", 
        QDir::tempPath()
    };
    
    for (const QString& badPath : dangerousPaths) {
        if (parentPath.startsWith(badPath)) {
            SECURE_LOG(ERROR, "EncryptionEngine", 
                QString("Security risk: Output path in insecure location: %1").arg(parentPath));
            return false;
        }
    }
    
    // Check if path is in a publicly shared directory
    QStringList sharedPaths = {
        "/home/shared", "/Users/Shared", "/Public", "/var/www", 
        QStandardPaths::writableLocation(QStandardPaths::PublicLocation)
    };
    
    for (const QString& sharedPath : sharedPaths) {
        if (parentPath.startsWith(sharedPath)) {
            SECURE_LOG(WARNING, "EncryptionEngine", 
                QString("Security warning: Output in potentially shared location: %1").arg(parentPath));
            // We don't return false but warn the user
        }
    }
    
    return true;
}

// Check and fix file permissions
bool EncryptionEngine::checkAndFixFilePermissions(const QString& filePath, QFileDevice::Permissions desiredPermissions)
{
    // Check if file exists
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists()) {
        SECURE_LOG(ERROR, "EncryptionEngine", 
            QString("Cannot check permissions, file does not exist: %1").arg(filePath));
        return false;
    }
    
    // Get current permissions
    QFileDevice::Permissions currentPermissions = fileInfo.permissions();
    
    // Check if permissions need fixing
    if (currentPermissions != desiredPermissions) {
        // Try to set the desired permissions
        if (QFile::setPermissions(filePath, desiredPermissions)) {
            SECURE_LOG(INFO, "EncryptionEngine", 
                QString("Successfully fixed file permissions on: %1").arg(filePath));
            return true;
        } else {
            SECURE_LOG(ERROR, "EncryptionEngine", 
                QString("Failed to set secure permissions on: %1").arg(filePath));
            return false;
        }
    }
    
    // Permissions already match what we want
    return true;
}