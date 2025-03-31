#include "cryptoprovider.h"
#include <QDebug>
#include <argon2.h>
#include <openssl/rand.h>

Argon2Provider::Argon2Provider()
{
    qDebug() << "Argon2 provider initialized";
}

Argon2Provider::~Argon2Provider()
{
    // No explicit cleanup needed
}

QByteArray Argon2Provider::deriveKey(const QByteArray &password, const QByteArray &salt,
                                     const QString &kdf, int iterations, int keySize)
{
    // Initialize a QByteArray to hold the derived key
    QByteArray key(keySize, 0);
    bool success = false;

    if (kdf == "Argon2")
    {
        // Determine memory cost - use reasonable defaults if not specified
        uint32_t memoryKb = 1 << 16; // 64 MB

        // Adjust iterations if too small
        uint32_t time_cost = iterations > 0 ? iterations : 3;

        // Parallelism factor
        uint32_t parallelism = 1;

        // Argon2id is the preferred variant for general use cases
        int success = argon2id_hash_raw(
                         time_cost,
                         memoryKb,
                         parallelism,
                         password.data(),
                         password.size(),
                         reinterpret_cast<const unsigned char *>(salt.data()),
                         salt.size(),
                         reinterpret_cast<unsigned char *>(key.data()),
                         key.size()) == ARGON2_OK;

        if (!success)
        {
            // Fall back to Argon2i if Argon2id fails
            qDebug() << "Argon2 Provider: Argon2id failed, trying Argon2i...";
            // For fallback to Argon2i
            int success = argon2i_hash_raw(
                             time_cost,
                             memoryKb,
                             parallelism,
                             password.data(),
                             password.size(),
                             reinterpret_cast<const unsigned char *>(salt.data()),
                             salt.size(),
                             reinterpret_cast<unsigned char *>(key.data()),
                             key.size()) == ARGON2_OK;
        }
    }
    else
    {
        qDebug() << "Argon2 Provider: Only Argon2 KDF is supported";
        key.fill(0); // Clear sensitive data
        return QByteArray();
    }

    if (!success)
    {
        qDebug() << "Argon2 Provider: Key derivation failed for KDF:" << kdf;
        key.fill(0); // Clear sensitive data
        return QByteArray();
    }

    return key;
}

bool Argon2Provider::encrypt(QFile &inputFile, QFile &outputFile, const QByteArray &key,
                             const QByteArray &iv, const QString &algorithm, bool useAuthentication)
{
    // Delegate encryption to OpenSSL since Argon2 is only a KDF
    qDebug() << "Argon2 Provider: Delegating encryption operation to OpenSSL provider";
    return m_opensslProvider.encrypt(inputFile, outputFile, key, iv, algorithm, useAuthentication);
}

bool Argon2Provider::decrypt(QFile &inputFile, QFile &outputFile, const QByteArray &key,
                             const QByteArray &iv, const QString &algorithm, bool useAuthentication)
{
    // Delegate decryption to OpenSSL since Argon2 is only a KDF
    qDebug() << "Argon2 Provider: Delegating decryption operation to OpenSSL provider";
    return m_opensslProvider.decrypt(inputFile, outputFile, key, iv, algorithm, useAuthentication);
}

QByteArray Argon2Provider::generateRandomBytes(int size)
{
    // Delegate to OpenSSL for random number generation
    return m_opensslProvider.generateRandomBytes(size);
}

bool Argon2Provider::isHardwareAccelerationSupported()
{
    // Argon2 doesn't have specific hardware acceleration,
    // so return the OpenSSL hardware acceleration status
    return m_opensslProvider.isHardwareAccelerationSupported();
}

QStringList Argon2Provider::supportedCiphers()
{
    // Delegate to OpenSSL for cipher support
    return m_opensslProvider.supportedCiphers();
}

QStringList Argon2Provider::supportedKDFs()
{
    // Argon2 provider primarily supports Argon2 only
    return {"Argon2"};
}