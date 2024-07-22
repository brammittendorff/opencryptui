#include "encryptionengine.h"
#include <QFile>
#include <QDebug>
#include <argon2.h>
#include <sodium.h>
#include <openssl/evp.h>

QByteArray EncryptionEngine::readKeyfile(const QString& keyfilePath) {
    if (keyfilePath.isEmpty()) {
        return QByteArray();
    }
    QFile keyfile(keyfilePath);
    if (!keyfile.open(QIODevice::ReadOnly)) {
        qDebug() << "Failed to open keyfile";
        return QByteArray();
    }
    return keyfile.readAll();
}

QByteArray EncryptionEngine::deriveKey(const QString& password, const QByteArray& salt, const QStringList& keyfilePaths, const QString& kdf, int iterations) {
    QByteArray key(EVP_MAX_KEY_LENGTH, 0);
    QByteArray passwordWithKeyfile = password.toUtf8();

    for (const QString &keyfilePath : keyfilePaths) {
        passwordWithKeyfile.append(readKeyfile(keyfilePath));
    }

    if (kdf == "PBKDF2") {
        if (!PKCS5_PBKDF2_HMAC(passwordWithKeyfile.data(), passwordWithKeyfile.size(), reinterpret_cast<const unsigned char*>(salt.data()), salt.size(), iterations, EVP_sha256(), key.size(), reinterpret_cast<unsigned char*>(key.data()))) {
            qDebug() << "PBKDF2 key derivation failed";
            return QByteArray();
        }
    } else if (kdf == "Argon2") {
        if (argon2i_hash_raw(iterations, 1 << 16, 1, passwordWithKeyfile.data(), passwordWithKeyfile.size(), reinterpret_cast<const unsigned char*>(salt.data()), salt.size(), reinterpret_cast<unsigned char*>(key.data()), key.size()) != ARGON2_OK) {
            qDebug() << "Argon2 key derivation failed";
            return QByteArray();
        }
    } else if (kdf == "Scrypt") {
        unsigned long long opslimit = iterations;
        if (crypto_pwhash_scryptsalsa208sha256(reinterpret_cast<unsigned char*>(key.data()), static_cast<unsigned long long>(key.size()),
                                               passwordWithKeyfile.constData(), static_cast<unsigned long long>(passwordWithKeyfile.size()),
                                               reinterpret_cast<const unsigned char*>(salt.data()), 
                                               opslimit,
                                               crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0) {
            qDebug() << "Scrypt key derivation failed";
            return QByteArray();
        }
    }

    qDebug() << "Key derived successfully using" << kdf << "key (hex):" << key.toHex();
    return key;
}

QByteArray EncryptionEngine::deriveKey(const QString &password, const QString &salt, const QString &kdf, int iterations, int keySize) {
    QByteArray key(keySize, 0);
    QByteArray passwordWithKeyfile = password.toUtf8();

    if (kdf == "PBKDF2") {
        if (!PKCS5_PBKDF2_HMAC(passwordWithKeyfile.data(), passwordWithKeyfile.size(), reinterpret_cast<const unsigned char*>(salt.data()), salt.size(), iterations, EVP_sha256(), key.size(), reinterpret_cast<unsigned char*>(key.data()))) {
            qDebug() << "PBKDF2 key derivation failed";
            return QByteArray();
        }
    } else if (kdf == "Argon2") {
        if (argon2i_hash_raw(iterations, 1 << 16, 1, passwordWithKeyfile.data(), passwordWithKeyfile.size(), reinterpret_cast<const unsigned char*>(salt.data()), salt.size(), reinterpret_cast<unsigned char*>(key.data()), key.size()) != ARGON2_OK) {
            qDebug() << "Argon2 key derivation failed";
            return QByteArray();
        }
    } else if (kdf == "Scrypt") {
        unsigned long long opslimit = iterations;
        if (crypto_pwhash_scryptsalsa208sha256(reinterpret_cast<unsigned char*>(key.data()), static_cast<unsigned long long>(key.size()),
                                               passwordWithKeyfile.constData(), static_cast<unsigned long long>(passwordWithKeyfile.size()),
                                               reinterpret_cast<const unsigned char*>(salt.data()), 
                                               opslimit,
                                               crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0) {
            qDebug() << "Scrypt key derivation failed";
            return QByteArray();
        }
    }

    return key;
}