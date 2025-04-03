#include "encryptionworker.h"
#include "logging/secure_logger.h"
#include "encryptionengine_diskops.h"
#include <QElapsedTimer>
#include <QFileInfo>
#include <QMessageBox>
#include <QPushButton>
#include <openssl/rand.h>

using namespace DiskOperations;

EncryptionWorker::EncryptionWorker(QObject *parent)
    : QObject(parent), isDisk(false), isHiddenVolume(false)
{
}

void EncryptionWorker::setParameters(const QString &path, const QString &password, const QString &algorithm,
                                     const QString &kdf, int iterations, bool useHMAC, bool encrypt, bool isFile, const QString &customHeader, const QStringList &keyfilePaths)
{
    this->path = path;
    this->password = password;
    this->algorithm = algorithm;
    this->kdf = kdf;
    this->iterations = iterations;
    this->useHMAC = useHMAC;
    this->encrypt = encrypt;
    this->isFile = isFile;
    this->isDisk = false;
    this->customHeader = customHeader;
    this->keyfilePaths = keyfilePaths;
}

void EncryptionWorker::setDiskParameters(const QString &diskPath, const QString &password, const QString &algorithm,
                                      const QString &kdf, int iterations, bool useHMAC, bool encrypt, const QStringList &keyfilePaths)
{
    this->path = diskPath;
    this->password = password;
    this->algorithm = algorithm;
    this->kdf = kdf;
    this->iterations = iterations;
    this->useHMAC = useHMAC;
    this->encrypt = encrypt;
    this->isFile = false;  // Not a file operation
    this->isDisk = true;   // This is a disk operation
    this->isHiddenVolume = false; // Not a hidden volume operation
    this->customHeader = "";  // No custom header for disk encryption
    this->keyfilePaths = keyfilePaths;
}

void EncryptionWorker::setDiskParametersWithHiddenVolume(const QString &diskPath, const QString &outerPassword, const QString &hiddenPassword, 
                                                      qint64 hiddenVolumeSize, const QString &algorithm, const QString &kdf, 
                                                      int iterations, bool useHMAC, const QStringList &keyfilePaths)
{
    // Set the standard disk parameters for the outer volume
    this->path = diskPath;
    this->password = outerPassword;
    this->hiddenPassword = hiddenPassword;
    this->hiddenVolumeSize = hiddenVolumeSize;
    this->algorithm = algorithm;
    this->kdf = kdf;
    this->iterations = iterations;
    this->useHMAC = useHMAC;
    this->encrypt = true; // Hidden volumes are only created during encryption
    this->isFile = false; // Not a file operation
    this->isDisk = true;  // This is a disk operation
    this->isHiddenVolume = true; // This is a hidden volume operation
    this->customHeader = ""; // No custom header for disk encryption
    this->keyfilePaths = keyfilePaths;
}

void EncryptionWorker::setBenchmarkParameters(const QStringList &algorithms, const QStringList &kdfs) {
    this->benchmarkAlgorithms = algorithms;
    this->benchmarkKdfs = kdfs;
}

qint64 EncryptionWorker::getFileSizeInBytes(const QString &path) {
    QFileInfo fileInfo(path);
    return fileInfo.size();
}

void EncryptionWorker::process()
{
    QElapsedTimer timer;
    timer.start();

    bool success = false;
    QString errorMessage;
    QByteArray salt(32, 0); // Salt for key derivation

    if (encrypt) {
        SECURE_LOG(DEBUG, "EncryptionWorker", "Generating random salt for encryption");
        if (RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), salt.size()) != 1) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionWorker", "Failed to generate cryptographically secure random salt");
            emit finished(false, "Failed to generate random salt");
            return;
        }
    } else {
        SECURE_LOG(DEBUG, "EncryptionWorker", QString("Opening encrypted file to read salt: %1").arg(path));
        QFile inputFile(path);
        if (!inputFile.open(QIODevice::ReadOnly)) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionWorker", QString("Failed to open input file: %1 (error: %2)")
                .arg(path).arg(inputFile.errorString()));
            emit finished(false, "Failed to open input file");
            return;
        }

        // Read the salt
        if (inputFile.read(salt.data(), salt.size()) != salt.size()) {
            SECURE_LOG(ERROR_LEVEL, "EncryptionWorker", 
                QString("Failed to read salt from file: %1 (corruption possible)").arg(path));
            emit finished(false, "Failed to read salt from file");
            return;
        }

        inputFile.close();
    }

    // Derive the key using the password and keyfile(s)
    SECURE_LOG(DEBUG, "EncryptionWorker", 
        QString("Deriving key with KDF: %1, iterations: %2, using keyfiles: %3")
        .arg(kdf)
        .arg(iterations)
        .arg(keyfilePaths.isEmpty() ? "No" : "Yes"));
        
    QByteArray key = engine.deriveKey(password, salt, keyfilePaths, kdf, iterations);

    if (key.isEmpty()) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionWorker", 
            QString("Key derivation failed using KDF: %1").arg(kdf));
        emit finished(false, "Key derivation failed");
        return;
    }
    
    SECURE_LOG(DEBUG, "EncryptionWorker", "Key derivation completed successfully");

    if (isDisk) {
        // Disk encryption/decryption
        if (encrypt) {
            if (isHiddenVolume) {
                // First, encrypt the outer volume
                success = engine.encryptDisk(path, password, algorithm, kdf, iterations, useHMAC, keyfilePaths);
                
                if (success) {
                    // Now create the hidden volume
                    QByteArray hiddenSalt(32, 0);
                    QByteArray hiddenIV(16, 0);
                    
                    // Generate new random salt and IV for the hidden volume
                    if (RAND_bytes(reinterpret_cast<unsigned char*>(hiddenSalt.data()), hiddenSalt.size()) != 1 ||
                        RAND_bytes(reinterpret_cast<unsigned char*>(hiddenIV.data()), hiddenIV.size()) != 1) {
                        emit finished(false, "Failed to generate random data for hidden volume");
                        return;
                    }
                    
                    // Create the hidden volume
                    success = DiskOperations::createHiddenVolume(path, hiddenVolumeSize, algorithm, kdf, 
                                                               iterations, useHMAC, hiddenSalt, hiddenIV);
                    
                    if (!success) {
                        emit finished(false, "Failed to create hidden volume");
                        return;
                    }
                    
                    // Now encrypt the hidden volume using the hidden password
                    success = engine.encryptDiskSection(path, hiddenPassword, algorithm, kdf, iterations, 
                                                      useHMAC, keyfilePaths, 
                                                      DISK_HIDDEN_HEADER_OFFSET + DISK_HEADER_SIZE, 
                                                      hiddenVolumeSize);
                }
            } else {
                // Standard disk encryption
                success = engine.encryptDisk(path, password, algorithm, kdf, iterations, useHMAC, keyfilePaths);
            }
        } else {
            // Disk decryption - determine if we're using the outer or hidden volume based on the password
            bool hasHidden;
            QString detectedAlgorithm, detectedKdf;
            int detectedIterations;
            bool detectedUseHMAC;
            QByteArray detectedSalt, detectedIV;
            
            // First try to read the main header
            if (DiskOperations::readEncryptionHeader(path, detectedAlgorithm, detectedKdf, detectedIterations, 
                                                  detectedUseHMAC, detectedSalt, detectedIV, hasHidden)) {
                // Try to decrypt with the main password
                QByteArray key = engine.deriveKey(password, detectedSalt, keyfilePaths, detectedKdf, detectedIterations);
                if (!key.isEmpty()) {
                    // If it's a hidden volume, check if we're trying to decrypt the outer or hidden volume
                    if (hasHidden) {
                        // Check if the hidden volume exists
                        HiddenVolumeInfo hiddenInfo;
                        if (DiskOperations::readHiddenVolumeHeader(path, hiddenInfo)) {
                            // Try the current password with the hidden volume as well
                            QByteArray hiddenKey = engine.deriveKey(password, hiddenInfo.salt, keyfilePaths, hiddenInfo.kdf, hiddenInfo.iterations);
                            if (!hiddenKey.isEmpty()) {
                                // If the password works for both, ask the user which one they want to decrypt
                                QMessageBox msgBox;
                                msgBox.setIcon(QMessageBox::Question);
                                msgBox.setText("This disk contains a hidden volume.");
                                msgBox.setInformativeText("Do you want to decrypt the outer volume or the hidden volume?");
                                QPushButton *outerButton = msgBox.addButton("Outer Volume", QMessageBox::ActionRole);
                                msgBox.addButton("Hidden Volume", QMessageBox::ActionRole);
                                msgBox.exec();
                                
                                QAbstractButton* clickedButton = msgBox.clickedButton();
                                if (clickedButton == outerButton) {
                                    // Decrypt the outer volume
                                    success = engine.decryptDisk(path, password, detectedAlgorithm, detectedKdf, 
                                                              detectedIterations, detectedUseHMAC, keyfilePaths);
                                } else {
                                    // Decrypt the hidden volume
                                    success = engine.decryptDiskSection(path, password, hiddenInfo.algorithm, hiddenInfo.kdf,
                                                                      hiddenInfo.iterations, hiddenInfo.useHMAC, keyfilePaths,
                                                                      hiddenInfo.offset, hiddenInfo.size);
                                }
                            } else {
                                // Password only works for outer volume
                                success = engine.decryptDisk(path, password, detectedAlgorithm, detectedKdf, 
                                                          detectedIterations, detectedUseHMAC, keyfilePaths);
                            }
                        } else {
                            // Couldn't read hidden volume, just decrypt the outer volume
                            success = engine.decryptDisk(path, password, detectedAlgorithm, detectedKdf, 
                                                      detectedIterations, detectedUseHMAC, keyfilePaths);
                        }
                    } else {
                        // No hidden volume, just decrypt the outer volume
                        success = engine.decryptDisk(path, password, detectedAlgorithm, detectedKdf, 
                                                  detectedIterations, detectedUseHMAC, keyfilePaths);
                    }
                } else {
                    // Try the hidden volume if it exists
                    if (hasHidden) {
                        HiddenVolumeInfo hiddenInfo;
                        if (DiskOperations::readHiddenVolumeHeader(path, hiddenInfo)) {
                            success = engine.decryptDiskSection(path, password, hiddenInfo.algorithm, hiddenInfo.kdf,
                                                              hiddenInfo.iterations, hiddenInfo.useHMAC, keyfilePaths,
                                                              hiddenInfo.offset, hiddenInfo.size);
                        } else {
                            emit finished(false, "Password doesn't match either volume");
                            return;
                        }
                    } else {
                        emit finished(false, "Invalid password");
                        return;
                    }
                }
            } else {
                emit finished(false, "Failed to read disk header");
                return;
            }
        }
    } else if (isFile) {
        // File encryption/decryption
        if (encrypt) {
            success = engine.encryptFile(path, password, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths);
        } else {
            success = engine.decryptFile(path, password, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths);
        }
    } else {
        // Folder encryption/decryption
        if (encrypt) {
            success = engine.encryptFolder(path, password, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths);
        } else {
            success = engine.decryptFolder(path, password, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths);
        }
    }

    double seconds = timer.elapsed() / 1000.0;
    emit estimatedTime(seconds);

    if (success) {
        emit progress(100);
        
        double fileSizeMB = getFileSizeInBytes(path) / (1024.0 * 1024.0);
        double mbps = fileSizeMB / seconds;
        
        SECURE_LOG(INFO, "EncryptionWorker", 
            QString("Operation completed successfully in %.2f seconds (%.2f MB/s)")
            .arg(seconds).arg(mbps));
            
        emit finished(true, QString());
        emit benchmarkResultReady(iterations, mbps, seconds * 1000, algorithm, kdf);
    } else {
        SECURE_LOG(ERROR_LEVEL, "EncryptionWorker", 
            QString("Operation failed for path: %1 (algorithm: %2, KDF: %3)")
            .arg(path).arg(algorithm).arg(kdf));
            
        emit finished(false, "Encryption/Decryption failed");
    }
}

void EncryptionWorker::runBenchmark() {
    SECURE_LOG(INFO, "EncryptionWorker", "Starting benchmark...");

    for (const auto &algo : benchmarkAlgorithms) {
        for (const auto &kdf : benchmarkKdfs) {
            benchmarkCipher(algo, kdf, true);
            if (algo == "AES-256-GCM" || algo == "ChaCha20-Poly1305" || 
                algo == "AES-256-CTR" || algo == "AES-256-CBC" || 
                algo == "AES-128-GCM" || algo == "AES-128-CTR" || 
                algo == "AES-192-GCM" || algo == "AES-192-CTR" || 
                algo == "AES-128-CBC" || algo == "AES-192-CBC" || 
                algo == "Camellia-256-CBC" || algo == "Camellia-128-CBC") {
                benchmarkCipher(algo, kdf, false);
            }
        }
    }

    SECURE_LOG(INFO, "EncryptionWorker", "Benchmark complete.");
}

void EncryptionWorker::benchmarkCipher(const QString &algorithm, const QString &kdf, bool useHardwareAcceleration) {
    if (kdf != "PBKDF2" && kdf != "Argon2" && kdf != "Scrypt") {
        SECURE_LOG(WARNING, "EncryptionWorker", 
            QString("Skipping unknown KDF: %1").arg(kdf));
        return;
    }

    // Use a smaller buffer size for benchmarking to avoid memory issues
    // 10MB is sufficient for benchmarking and less likely to cause memory pressure
    const int dataSize = 10 * 1024 * 1024; // 10 MB instead of 100 MB
    
    // Only allocate the memory if we can
    QByteArray testData;
    try {
        testData.resize(dataSize);
        testData.fill('A');
    } catch (const std::bad_alloc&) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionWorker", "Memory allocation failed for benchmark data");
        return;
    }
    
    QByteArray key(32, 'K');
    QByteArray iv(16, 'I');
    QByteArray salt(16, 'S');
    int iterations = 10;

    QElapsedTimer timer;
    timer.start();

    const EVP_CIPHER *cipher = engine.getCipher(algorithm);

    if (!cipher) {
        SECURE_LOG(WARNING, "EncryptionWorker", 
            QString("Skipping %1 - not supported").arg(algorithm));
        return;
    }

    QStringList keyfilePaths; // If no keyfiles, use an empty QStringList
    key = engine.deriveKey("password", salt, keyfilePaths, kdf, iterations);
    if (key.isEmpty()) {
        SECURE_LOG(ERROR, "EncryptionWorker", 
            QString("Key derivation failed for KDF: %1").arg(kdf));
        return;
    }

    // Perform encryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        SECURE_LOG(ERROR, "EncryptionWorker", "Failed to create EVP_CIPHER_CTX");
        return;
    }

    if (!EVP_EncryptInit_ex(ctx, cipher, nullptr,
                            reinterpret_cast<const unsigned char *>(key.data()),
                            reinterpret_cast<const unsigned char *>(iv.data()))) {
        SECURE_LOG(ERROR, "EncryptionWorker", "EVP_EncryptInit_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // Only allocate the ciphertext buffer if we can
    QByteArray ciphertext;
    try {
        ciphertext.resize(testData.size() + EVP_MAX_BLOCK_LENGTH);
    } catch (const std::bad_alloc&) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionWorker", "Memory allocation failed for ciphertext buffer");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    
    int len = 0;
    int ciphertextLen = 0;
    
    bool encryptSuccess = EVP_EncryptUpdate(ctx, 
                                reinterpret_cast<unsigned char *>(ciphertext.data()), 
                                &len,
                                reinterpret_cast<const unsigned char *>(testData.data()), 
                                testData.size()) == 1;
    
    if (!encryptSuccess) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionWorker", "EVP_EncryptUpdate failed");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    
    ciphertextLen += len;
    
    encryptSuccess = EVP_EncryptFinal_ex(ctx, 
                            reinterpret_cast<unsigned char *>(ciphertext.data()) + len, 
                            &len) == 1;
                            
    if (!encryptSuccess) {
        SECURE_LOG(ERROR_LEVEL, "EncryptionWorker", "EVP_EncryptFinal_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    
    ciphertextLen += len;
    
    // Always free the cipher context
    EVP_CIPHER_CTX_free(ctx);
    
    // Clear memory as soon as we're done with it to reduce memory footprint
    ciphertext.clear();
    testData.clear();

    qint64 elapsed = timer.elapsed();
    double throughput = (dataSize / (1024.0 * 1024.0)) / (elapsed / 1000.0);

    emit benchmarkResultReady(iterations, throughput, elapsed, algorithm, kdf);
}
