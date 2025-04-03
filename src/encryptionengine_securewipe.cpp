#include "encryptionengine.h"
#include "logging/secure_logger.h"
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QTimer>
#include <QProcess>
#include <algorithm> // For std::min

// Secure file deletion with multiple passes
bool EncryptionEngine::secureDeleteFile(const QString& filePath, int passes)
{
    if (passes < 1) passes = 3; // Default to 3 passes for good security
    
    QFile file(filePath);
    QFileInfo fileInfo(filePath);
    
    // Check if file exists and is writable
    if (!fileInfo.exists() || !fileInfo.isWritable()) {
        SECURE_LOG(ERROR, "EncryptionEngine", 
            QString("Cannot securely delete file: %1 - File does not exist or is not writable").arg(filePath));
        return false;
    }
    
    // Get file size for overwriting
    qint64 fileSize = fileInfo.size();
    if (fileSize <= 0) {
        // Empty file, just delete it
        return QFile::remove(filePath);
    }
    
    // Open file for writing
    if (!file.open(QIODevice::ReadWrite)) {
        SECURE_LOG(ERROR, "EncryptionEngine", 
            QString("Cannot open file for secure deletion: %1").arg(filePath));
        return false;
    }
    
    // Create data buffers of different patterns
    QByteArray randomBuffer(std::min(fileSize, static_cast<qint64>(1024 * 1024)), 0); // Max 1MB buffer
    QByteArray zeroBuffer(randomBuffer.size(), 0);
    QByteArray oneBuffer(randomBuffer.size(), 0xFF);
    
    try {
        // Multiple secure overwrite passes
        for (int pass = 0; pass < passes; pass++) {
            // Reset to beginning of file
            if (!file.seek(0)) {
                SECURE_LOG(ERROR, "EncryptionEngine", 
                    QString("Failed to seek to beginning of file for pass %1: %2").arg(pass).arg(filePath));
                file.close();
                return false;
            }
            
            // Pattern selection based on pass number
            QByteArray* currentBuffer = nullptr;
            QByteArray randomData; // Declare outside switch for scope reasons
            
            switch (pass % 3) {
                case 0:
                    // Random data pass
                    randomData = generateSecureRandomBytes(randomBuffer.size(), false);
                    randomBuffer = randomData;
                    currentBuffer = &randomBuffer;
                    break;
                case 1:
                    // All zeros pass
                    currentBuffer = &zeroBuffer;
                    break;
                case 2:
                    // All ones pass
                    currentBuffer = &oneBuffer;
                    break;
            }
            
            // Write in chunks
            qint64 remaining = fileSize;
            while (remaining > 0) {
                QByteArray writeBuffer;
                if (remaining >= currentBuffer->size()) {
                    writeBuffer = *currentBuffer;
                } else {
                    writeBuffer = currentBuffer->left(remaining);
                }
                
                // Write the pattern
                qint64 bytesWritten = file.write(writeBuffer);
                if (bytesWritten <= 0) {
                    SECURE_LOG(ERROR, "EncryptionEngine", 
                        QString("Failed to write during secure deletion pass %1: %2").arg(pass).arg(filePath));
                    file.close();
                    return false;
                }
                
                // Update remaining bytes
                remaining -= bytesWritten;
                
                // Explicitly flush to ensure data is written
                file.flush();
            }
        }
        
        // Flush all data to disk
        file.flush();
        
        // Close file before rename/deletion
        file.close();
        
        // Rename the file to hide its original name
        QString tempName = filePath + ".tmp" + QString::number(QDateTime::currentMSecsSinceEpoch());
        QString fileToDelete = filePath;
        
        if (!QFile::rename(filePath, tempName)) {
            SECURE_LOG(WARNING, "EncryptionEngine", 
                QString("Failed to rename file during secure deletion: %1").arg(filePath));
            // Continue with deletion attempt anyway
        } else {
            // Use the new temp name for final deletion
            fileToDelete = tempName;
        }
        
        // Finally delete the file
        if (!QFile::remove(fileToDelete)) {
            SECURE_LOG(ERROR, "EncryptionEngine", 
                QString("Failed to delete file after secure overwrite: %1").arg(fileToDelete));
            return false;
        }
        
        SECURE_LOG(INFO, "EncryptionEngine", 
            QString("Securely deleted file with %1 passes: %2").arg(passes).arg(fileInfo.fileName()));
        
        return true;
    }
    catch (const std::exception& e) {
        SECURE_LOG(ERROR, "EncryptionEngine", 
            QString("Exception during secure file deletion: %1").arg(e.what()));
        
        // Make sure file is closed
        if (file.isOpen()) {
            file.close();
        }
        
        return false;
    }
}

// Securely delete plaintext after encryption
bool EncryptionEngine::secureDeletePlaintext(const QString& plaintextFilePath)
{
    return secureDeleteFile(plaintextFilePath, 3);
}

// Implement inode scrubbing to completely remove file traces
bool EncryptionEngine::scrubFileInode(const QString& filePath)
{
    // This is a Linux-specific implementation using the shred command
    // It tries to hide all traces of file existence
    
#ifdef Q_OS_UNIX
    // Create a QProcess to run the external command
    QProcess process;
    QStringList args;
    
    // Configure shred for thorough deletion (-u removes the file, -z adds a final zero pass, -n 3 is 3 passes)
    args << "-u" << "-z" << "-n" << "3" << filePath;
    
    // Execute shred command
    process.start("shred", args);
    
    // Wait for the process to finish with a timeout
    if (!process.waitForFinished(30000)) { // 30 second timeout
        SECURE_LOG(ERROR, "EncryptionEngine", 
            QString("Timeout while running shred on file: %1").arg(filePath));
        process.kill();
        return false;
    }
    
    // Check the exit code
    if (process.exitCode() != 0) {
        SECURE_LOG(ERROR, "EncryptionEngine", 
            QString("Shred command failed with exit code %1: %2")
            .arg(process.exitCode())
            .arg(QString(process.readAllStandardError())));
        return false;
    }
    
    SECURE_LOG(INFO, "EncryptionEngine", 
        QString("Successfully scrubbed file inode: %1").arg(filePath));
    return true;
    
#else
    // For non-Unix systems, fall back to regular secure delete
    SECURE_LOG(INFO, "EncryptionEngine", 
        QString("Inode scrubbing not supported on this platform, using secure delete for: %1").arg(filePath));
    return secureDeleteFile(filePath, 7); // Use more passes as compensation
#endif
}