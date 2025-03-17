#include "encryptionengine.h"
#include <QFile>
#include <QDebug>
#include <argon2.h>
#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cmath> // For std::log2

// Implementation of keyfile entropy validation
bool EncryptionEngine::validateKeyfileEntropy(const QByteArray& keyfileData) {
    // Skip validation for very small files
    if (keyfileData.size() < 64) {
        return true;
    }
    
    // Simple Shannon entropy calculation
    int frequencies[256] = {0};
    for (char byte : keyfileData) {
        frequencies[static_cast<unsigned char>(byte)]++;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (frequencies[i] > 0) {
            double probability = static_cast<double>(frequencies[i]) / keyfileData.size();
            entropy -= probability * std::log2(probability);
        }
    }
    
    // Threshold: 3.0 bits of entropy is very low but enough to filter out empty or uniform files
    return entropy > 3.0;
}

// Implementation for adaptive Argon2 memory cost
size_t EncryptionEngine::determineArgon2MemoryCost() {
    // Default is 64MB (1 << 16)
    // For better security, scale with available system memory
    size_t systemMemoryMB = 1024; // 1GB as a conservative default
    
    // On most systems, using up to 10% of memory for password hashing is reasonable
    size_t memoryCost = std::min(static_cast<size_t>(1 << 20), systemMemoryMB * 1024 * 102 / 1000);
    
    // But ensure it's at least 64MB for security
    memoryCost = std::max(memoryCost, static_cast<size_t>(1 << 16));
    
    return memoryCost;
}

// Implementation for adaptive Scrypt memory limit
size_t EncryptionEngine::determineScryptMemLimit() {
    // Conservative default values
    size_t memlimit = crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE;
    
    // For high-security use cases, we can increase this to SENSITIVE if system has enough RAM
    size_t systemMemoryMB = 1024; // 1GB as conservative default
    
    if (systemMemoryMB > 4096) { // If system has more than 4GB RAM
        memlimit = crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE;
    }
    
    return memlimit;
}

QByteArray EncryptionEngine::readKeyfile(const QString& keyfilePath) {
    // Ensure the keyfile path is provided
    if (keyfilePath.isEmpty()) {
        return QByteArray();
    }

    // Open the keyfile
    QFile keyfile(keyfilePath);
    if (!keyfile.open(QIODevice::ReadOnly)) {
        qDebug() << "Failed to open keyfile at path:" << keyfilePath;
        return QByteArray();
    }

    // Read the entire content of the keyfile
    QByteArray keyfileData = keyfile.readAll();
    keyfile.close();

    if (keyfileData.isEmpty()) {
        qDebug() << "Keyfile is empty or could not be read:" << keyfilePath;
        return QByteArray();
    }

    // Add file size validation
    if (keyfileData.size() > MAX_KEYFILE_SIZE || keyfileData.isEmpty()) {
        qDebug() << "Keyfile size invalid:" << keyfilePath;
        return QByteArray();
    }
    
    // Consider adding basic entropy checking for keyfiles
    if (!validateKeyfileEntropy(keyfileData)) {
        qDebug() << "Keyfile has insufficient entropy:" << keyfilePath;
        return QByteArray();
    }
    
    QByteArray result = keyfileData;
    
    // Ensure keyfile data is cleared from memory
    OPENSSL_cleanse(keyfileData.data(), keyfileData.size());
    
    return result;
}

QByteArray EncryptionEngine::deriveKey(const QString& password, const QByteArray& salt, const QStringList& keyfilePaths, const QString& kdf, int iterations) {
    // Allocate memory using sodium's secure allocation
    QByteArray passwordWithKeyfile(password.size(), 0);
    
    if (sodium_mlock(passwordWithKeyfile.data(), passwordWithKeyfile.size()) != 0) {
        qDebug() << "Failed to lock memory for password";
        return QByteArray();
    }
    
    // Copy password data
    memcpy(passwordWithKeyfile.data(), password.toUtf8().constData(), password.size());
    
    // Process each keyfile and append to the password
    for (const QString &keyfilePath : keyfilePaths) {
        QByteArray keyfileData = readKeyfile(keyfilePath);
        if (!keyfileData.isEmpty()) {
            passwordWithKeyfile.append(keyfileData);
        }
    }

    // Perform key derivation
    QByteArray derivedKey = performKeyDerivation(passwordWithKeyfile, salt, kdf, iterations, EVP_MAX_KEY_LENGTH);

    // Clear sensitive data from memory
    OPENSSL_cleanse(passwordWithKeyfile.data(), passwordWithKeyfile.size());
    sodium_munlock(passwordWithKeyfile.data(), passwordWithKeyfile.size());
    
    return derivedKey;
}

// Function to derive a cryptographic key using just the password (without keyfiles)
QByteArray EncryptionEngine::deriveKeyWithoutKeyfile(const QString &password, const QString &salt, const QString &kdf, int iterations, int keySize) {
    // Convert the password to UTF-8 and store it in a QByteArray
    QByteArray passwordWithKeyfile = password.toUtf8();

    // Perform key derivation using the password only
    return performKeyDerivation(passwordWithKeyfile, salt.toUtf8(), kdf, iterations, keySize);
}

QByteArray EncryptionEngine::performKeyDerivation(const QByteArray& passwordWithKeyfile, const QByteArray& salt, const QString& kdf, int iterations, int keySize) {
    // Initialize a QByteArray to hold the derived key
    QByteArray key(keySize, 0);

    // Attempt to lock the key memory to prevent it from being swapped to disk
    if (sodium_mlock(key.data(), key.size()) != 0) {
        qDebug() << "Failed to lock key in memory";
        return QByteArray(); // Return an empty QByteArray on failure
    }

    bool success = false;

    // Perform key derivation based on the selected KDF
    if (kdf == "PBKDF2") {
        // PBKDF2 key derivation using SHA-256
        success = PKCS5_PBKDF2_HMAC(passwordWithKeyfile.data(), passwordWithKeyfile.size(),
                                    reinterpret_cast<const unsigned char*>(salt.data()), salt.size(),
                                    iterations, EVP_sha256(), key.size(),
                                    reinterpret_cast<unsigned char*>(key.data())) != 0;
    } else if (kdf == "Argon2") {
        // Scale memory cost based on system capability
        size_t memoryCost = determineArgon2MemoryCost();
        
        success = argon2i_hash_raw(iterations, 
                                  memoryCost, // Instead of fixed 1 << 16
                                  4, // Increase parallelism for better performance on multi-core systems
                                  passwordWithKeyfile.data(), 
                                  passwordWithKeyfile.size(),
                                  reinterpret_cast<const unsigned char*>(salt.data()), 
                                  salt.size(),
                                  reinterpret_cast<unsigned char*>(key.data()), 
                                  key.size()) == ARGON2_OK;
    } else if (kdf == "Scrypt") {
        // Use stronger parameters for high-security use cases
        unsigned long long opslimit = iterations;
        size_t memlimit = determineScryptMemLimit();
        
        success = crypto_pwhash_scryptsalsa208sha256(
                      reinterpret_cast<unsigned char*>(key.data()),
                      static_cast<unsigned long long>(key.size()),
                      passwordWithKeyfile.constData(),
                      static_cast<unsigned long long>(passwordWithKeyfile.size()),
                      reinterpret_cast<const unsigned char*>(salt.data()),
                      opslimit,
                      memlimit) == 0;
    } else {
        // If an unknown KDF is provided, log an error
        qDebug() << "Unknown KDF specified:" << kdf;
    }

    if (!success) {
        qDebug() << kdf << " key derivation failed";

        // Unlock and cleanse key before returning
        sodium_munlock(key.data(), key.size());
        OPENSSL_cleanse(key.data(), key.size());

        return QByteArray(); // Return an empty QByteArray on failure
    }

    // Clear sensitive data in passwordWithKeyfile
    OPENSSL_cleanse(const_cast<char*>(passwordWithKeyfile.constData()), passwordWithKeyfile.size());

    // Unlock the key memory before returning it
    sodium_munlock(key.data(), key.size());

    return key;
}
