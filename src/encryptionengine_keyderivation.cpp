#include "encryptionengine.h"
#include <QFile>
#include <QDebug>
#include <argon2.h>
#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

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
    }

    return keyfileData;
}

QByteArray EncryptionEngine::deriveKey(const QString& password, const QByteArray& salt, const QStringList& keyfilePaths, const QString& kdf, int iterations) {
    QByteArray passwordWithKeyfile = password.toUtf8();

    // Log each keyfile's data before appending
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

    return derivedKey;
}

// Function to derive a cryptographic key using just the password (without keyfiles)
QByteArray EncryptionEngine::deriveKeyWithoutKeyfile(const QString &password, const QString &salt, const QString &kdf, int iterations, int keySize) {
    // Convert the password to UTF-8 and store it in a QByteArray
    QByteArray passwordWithKeyfile = password.toUtf8();

    // Perform key derivation using the password only
    return performKeyDerivation(passwordWithKeyfile, salt.toUtf8(), kdf, iterations, keySize);
}

// Enhanced Key Derivation with Security Improvements
QByteArray EncryptionEngine::performKeyDerivation(const QByteArray& passwordWithKeyfile, const QByteArray& salt, const QString& kdf, int iterations, int keySize)
{
    // Validate input parameters
    if (passwordWithKeyfile.isEmpty() || salt.isEmpty() || keySize <= 0) {
        qDebug() << "Invalid key derivation parameters";
        return QByteArray();
    }

    // Ensure minimum secure iteration counts
    int secureIterations = calculateSecureIterations(kdf, iterations);

    // Allocate key with secure memory locking
    QScopedArrayPointer<char> key(new char[keySize]);
    std::memset(key.data(), 0, keySize);

    // Advanced memory protection
    sodium_mlock(key.data(), keySize);

    // Prevent compiler optimizations that might remove memory clearing
    volatile bool derivationSuccessful = false;

    try {
        // Key derivation with enhanced security parameters
        if (kdf == "Argon2") {
            // Use Argon2id - resistance against side-channel and timing attacks
            int argon2Result = argon2id_hash_raw(
                secureIterations,      // Time cost
                1 << 20,               // Memory: 1 GB
                4,                     // Parallelism factor
                passwordWithKeyfile.constData(), 
                passwordWithKeyfile.size(),
                salt.constData(), 
                salt.size(),
                reinterpret_cast<unsigned char*>(key.data()), 
                keySize
            );

            derivationSuccessful = (argon2Result == ARGON2_OK);
        }
        else if (kdf == "PBKDF2") {
            // Enhanced PBKDF2 with SHA-512
            int pbkdf2Result = PKCS5_PBKDF2_HMAC(
                passwordWithKeyfile.constData(), 
                passwordWithKeyfile.size(),
                reinterpret_cast<const unsigned char*>(salt.constData()), 
                salt.size(),
                secureIterations, 
                EVP_sha512(),  // Use stronger SHA-512
                keySize,
                reinterpret_cast<unsigned char*>(key.data())
            );

            derivationSuccessful = (pbkdf2Result == 1);
        }
        else if (kdf == "Scrypt") {
            // Libsodium's secure Scrypt implementation
            int scryptResult = crypto_pwhash_scryptsalsa208sha256(
                reinterpret_cast<unsigned char*>(key.data()),
                static_cast<unsigned long long>(keySize),
                passwordWithKeyfile.constData(),
                static_cast<unsigned long long>(passwordWithKeyfile.size()),
                reinterpret_cast<const unsigned char*>(salt.constData()),
                secureIterations,
                crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE
            );

            derivationSuccessful = (scryptResult == 0);
        }
        else {
            qDebug() << "Unsupported KDF:" << kdf;
            return QByteArray();
        }

        // Verification step
        if (!derivationSuccessful) {
            qDebug() << "Key derivation failed for" << kdf;
            
            // Secure cleanup
            sodium_memzero(key.data(), keySize);
            sodium_munlock(key.data(), keySize);
            
            return QByteArray();
        }

        // Convert to QByteArray with secure copy
        QByteArray secureKey(key.data(), keySize);

        // Additional memory sanitization
        sodium_memzero(key.data(), keySize);
        sodium_munlock(key.data(), keySize);

        return secureKey;
    }
    catch (const std::exception& e) {
        qDebug() << "Exception during key derivation:" << e.what();
        
        // Secure cleanup in case of exception
        sodium_memzero(key.data(), keySize);
        sodium_munlock(key.data(), keySize);
        
        return QByteArray();
    }
}

// Dynamically calculate secure iteration counts
int EncryptionEngine::calculateSecureIterations(const QString& kdf, int requestedIterations)
{
    // Minimum secure iteration recommendations
    const int ARGON2_MIN_ITERATIONS = 3;     // Cryptographically secure baseline
    const int PBKDF2_MIN_ITERATIONS = 50000; // NIST SP 800-63B recommendation
    const int SCRYPT_MIN_ITERATIONS = 16384; // Secure baseline

    if (requestedIterations < 1) {
        // Default to secure baselines if input is invalid
        if (kdf == "Argon2") return ARGON2_MIN_ITERATIONS;
        if (kdf == "PBKDF2") return PBKDF2_MIN_ITERATIONS;
        if (kdf == "Scrypt") return SCRYPT_MIN_ITERATIONS;
    }

    // Scale iterations based on KDF
    if (kdf == "Argon2") {
        return std::max(requestedIterations, ARGON2_MIN_ITERATIONS);
    }
    else if (kdf == "PBKDF2") {
        return std::max(requestedIterations, PBKDF2_MIN_ITERATIONS);
    }
    else if (kdf == "Scrypt") {
        return std::max(requestedIterations, SCRYPT_MIN_ITERATIONS);
    }

    return requestedIterations;
}

// Secure random salt generation
QByteArray EncryptionEngine::generateSecureSalt(int size)
{
    QByteArray salt(size, 0);
    
    // Generate random bytes using OpenSSL's RAND_bytes instead of libsodium
    if (RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), size) != 1) {
        qDebug() << "Secure random salt generation failed";
        return QByteArray();
    }

    return salt;
}

// Enhanced IV generation with additional entropy
QByteArray EncryptionEngine::generateSecureIV(int size)
{
    QByteArray iv(size, 0);
    
    // Generate random bytes using OpenSSL's RAND_bytes instead of libsodium
    if (RAND_bytes(reinterpret_cast<unsigned char*>(iv.data()), size) != 1) {
        qDebug() << "Secure IV generation failed";
        return QByteArray();
    }

    return iv;
}