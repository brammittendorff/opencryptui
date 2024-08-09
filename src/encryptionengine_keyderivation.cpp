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
        // Argon2i key derivation
        success = argon2i_hash_raw(iterations, 1 << 16, 1,
                                   passwordWithKeyfile.data(), passwordWithKeyfile.size(),
                                   reinterpret_cast<const unsigned char*>(salt.data()), salt.size(),
                                   reinterpret_cast<unsigned char*>(key.data()), key.size()) == ARGON2_OK;
    } else if (kdf == "Scrypt") {
        // Scrypt key derivation
        unsigned long long opslimit = iterations;
        success = crypto_pwhash_scryptsalsa208sha256(reinterpret_cast<unsigned char*>(key.data()),
                                                     static_cast<unsigned long long>(key.size()),
                                                     passwordWithKeyfile.constData(),
                                                     static_cast<unsigned long long>(passwordWithKeyfile.size()),
                                                     reinterpret_cast<const unsigned char*>(salt.data()), 
                                                     opslimit,
                                                     crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) == 0;
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
