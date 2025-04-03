#include "cryptoprovider.h"
#include "logging/secure_logger.h"
#include <sodium.h>

LibsodiumProvider::LibsodiumProvider()
{
    // Initialize libsodium
    if (sodium_init() < 0)
    {
        SECURE_LOG(ERROR_LEVEL, "LibsodiumProvider", "Failed to initialize libsodium");
        throw std::runtime_error("Failed to initialize libsodium");
    }
    SECURE_LOG(INFO, "LibsodiumProvider", "Libsodium provider initialized successfully");
}

LibsodiumProvider::~LibsodiumProvider()
{
    // No explicit cleanup needed for libsodium
}

QByteArray LibsodiumProvider::deriveKey(const QByteArray &password, const QByteArray &salt,
                                        const QString &kdf, int iterations, int keySize)
{
    QByteArray key(keySize, 0);

    if (kdf == "Argon2")
    {
        // libsodium uses Argon2id by default (preferred over Argon2i)
        unsigned long long ops = iterations > 0 ? iterations : crypto_pwhash_OPSLIMIT_INTERACTIVE;
        int result = crypto_pwhash(
            reinterpret_cast<unsigned char *>(key.data()), key.size(),
            password.constData(), password.size(),
            reinterpret_cast<const unsigned char *>(salt.constData()),
            ops, crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_DEFAULT);

        if (result != 0)
        {
            SECURE_LOG(ERROR_LEVEL, "LibsodiumProvider", "Argon2 key derivation failed");
            sodium_memzero(key.data(), key.size());
            return QByteArray();
        }
    }
    else if (kdf == "Scrypt")
    {
        // Use libsodium's scrypt implementation
        unsigned long long opslimit = iterations > 0 ? iterations : crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE;
        int result = crypto_pwhash_scryptsalsa208sha256(
            reinterpret_cast<unsigned char *>(key.data()),
            static_cast<unsigned long long>(key.size()),
            password.constData(),
            static_cast<unsigned long long>(password.size()),
            reinterpret_cast<const unsigned char *>(salt.constData()),
            opslimit,
            crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);

        if (result != 0)
        {
            SECURE_LOG(ERROR_LEVEL, "LibsodiumProvider", "Scrypt key derivation failed");
            sodium_memzero(key.data(), key.size());
            return QByteArray();
        }
    }
    else
    {
        SECURE_LOG(WARNING, "LibsodiumProvider", 
            QString("Unsupported KDF specified: %1").arg(kdf));
        sodium_memzero(key.data(), key.size());
        return QByteArray();
    }

    return key;
}

bool LibsodiumProvider::encrypt(QFile &inputFile, QFile &outputFile, const QByteArray &key,
                                const QByteArray &iv, const QString &algorithm, bool useAuthentication)
{
    SECURE_LOG(DEBUG, "LibsodiumProvider", 
        QString("Encryption started with algorithm: %1").arg(algorithm));

    // Map OpenSSL algorithm names to libsodium operations
    if (algorithm.contains("ChaCha20-Poly1305") || useAuthentication)
    {
        // Use XChaCha20-Poly1305 for AEAD
        return encryptWithXChaCha20Poly1305(inputFile, outputFile, key, iv);
    }
    else if (algorithm.contains("AES") || algorithm.contains("Camellia"))
    {
        // Use XChaCha20 secretstream for other ciphers
        return encryptWithSecretStream(inputFile, outputFile, key, iv);
    }
    else
    {
        SECURE_LOG(WARNING, "LibsodiumProvider", 
            QString("Unsupported algorithm: %1").arg(algorithm));
        return false;
    }
}

bool LibsodiumProvider::decrypt(QFile &inputFile, QFile &outputFile, const QByteArray &key,
                                const QByteArray &iv, const QString &algorithm, bool useAuthentication)
{
    SECURE_LOG(DEBUG, "LibsodiumProvider", 
        QString("Decryption started with algorithm: %1").arg(algorithm));

    // Map OpenSSL algorithm names to libsodium operations
    if (algorithm.contains("ChaCha20-Poly1305") || useAuthentication)
    {
        // Use XChaCha20-Poly1305 for AEAD
        return decryptWithXChaCha20Poly1305(inputFile, outputFile, key, iv);
    }
    else if (algorithm.contains("AES") || algorithm.contains("Camellia"))
    {
        // Use XChaCha20 secretstream for other ciphers
        return decryptWithSecretStream(inputFile, outputFile, key, iv);
    }
    else
    {
        SECURE_LOG(WARNING, "LibsodiumProvider", 
            QString("Unsupported algorithm: %1").arg(algorithm));
        return false;
    }
}

QByteArray LibsodiumProvider::generateRandomBytes(int size)
{
    QByteArray bytes(size, 0);
    randombytes_buf(bytes.data(), size);
    return bytes;
}

bool LibsodiumProvider::isHardwareAccelerationSupported()
{
    // libsodium automatically uses hardware acceleration if available
    return true;
}

QStringList LibsodiumProvider::supportedCiphers()
{
    return {
        "ChaCha20-Poly1305", // Native support
        "AES-256-GCM",       // Mapped to ChaCha20-Poly1305
        "AES-256-CTR",       // Mapped to secretstream
        "AES-256-CBC",       // Mapped to secretstream
        "AES-128-GCM",       // Mapped to ChaCha20-Poly1305
        "AES-128-CTR",       // Mapped to secretstream
        "AES-192-GCM",       // Mapped to ChaCha20-Poly1305
        "AES-192-CTR"        // Mapped to secretstream
    };
}

QStringList LibsodiumProvider::supportedKDFs()
{
    // Only return what's actually natively supported by libsodium
    return {"Argon2", "Scrypt"};
}

bool LibsodiumProvider::encryptWithXChaCha20Poly1305(QFile &inputFile, QFile &outputFile,
                                                     const QByteArray &key, const QByteArray &nonce)
{
    const size_t CHUNK_SIZE = 4096;
    const size_t ENCRYPTED_CHUNK_SIZE = CHUNK_SIZE + crypto_aead_xchacha20poly1305_ietf_ABYTES;

    QByteArray buffer(CHUNK_SIZE, 0);
    QByteArray encryptedChunk(ENCRYPTED_CHUNK_SIZE, 0);
    unsigned long long encryptedLen;

    while (!inputFile.atEnd())
    {
        qint64 bytesRead = inputFile.read(buffer.data(), CHUNK_SIZE);
        if (bytesRead <= 0)
            break;

        if (crypto_aead_xchacha20poly1305_ietf_encrypt(
                reinterpret_cast<unsigned char *>(encryptedChunk.data()), &encryptedLen,
                reinterpret_cast<const unsigned char *>(buffer.constData()), bytesRead,
                nullptr, 0, // no additional data
                nullptr,    // no previous tag
                reinterpret_cast<const unsigned char *>(nonce.constData()),
                reinterpret_cast<const unsigned char *>(key.constData())) != 0)
        {
            SECURE_LOG(ERROR_LEVEL, "LibsodiumProvider", 
                "XChaCha20-Poly1305 encryption failed");
            return false;
        }

        outputFile.write(encryptedChunk.constData(), encryptedLen);
    }

    SECURE_LOG(INFO, "LibsodiumProvider", 
        "XChaCha20-Poly1305 encryption completed successfully");
    return true;
}

bool LibsodiumProvider::decryptWithXChaCha20Poly1305(QFile &inputFile, QFile &outputFile,
                                                     const QByteArray &key, const QByteArray &nonce)
{
    const size_t CHUNK_SIZE = 4096;
    const size_t ENCRYPTED_CHUNK_SIZE = CHUNK_SIZE + crypto_aead_xchacha20poly1305_ietf_ABYTES;

    QByteArray encryptedChunk(ENCRYPTED_CHUNK_SIZE, 0);
    QByteArray decryptedChunk(CHUNK_SIZE, 0);
    unsigned long long decryptedLen;

    while (!inputFile.atEnd())
    {
        qint64 bytesRead = inputFile.read(encryptedChunk.data(), ENCRYPTED_CHUNK_SIZE);
        if (bytesRead <= 0)
            break;

        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                reinterpret_cast<unsigned char *>(decryptedChunk.data()), &decryptedLen,
                nullptr, // no previous tag
                reinterpret_cast<const unsigned char *>(encryptedChunk.constData()), bytesRead,
                nullptr, 0, // no additional data
                reinterpret_cast<const unsigned char *>(nonce.constData()),
                reinterpret_cast<const unsigned char *>(key.constData())) != 0)
        {
            SECURE_LOG(ERROR_LEVEL, "LibsodiumProvider", 
                "XChaCha20-Poly1305 decryption failed (authentication error)");
            return false;
        }

        outputFile.write(decryptedChunk.constData(), decryptedLen);
    }

    SECURE_LOG(INFO, "LibsodiumProvider", 
        "XChaCha20-Poly1305 decryption completed successfully");
    return true;
}

bool LibsodiumProvider::encryptWithSecretStream(QFile &inputFile, QFile &outputFile,
                                                const QByteArray &key, const QByteArray &nonce)
{
    crypto_secretstream_xchacha20poly1305_state state;

    if (crypto_secretstream_xchacha20poly1305_init_push(
            &state,
            reinterpret_cast<unsigned char *>(const_cast<char *>(nonce.constData())),
            reinterpret_cast<const unsigned char *>(key.constData())) != 0)
    {
        SECURE_LOG(ERROR_LEVEL, "LibsodiumProvider", 
            "Failed to initialize secretstream encryption");
        return false;
    }

    const size_t CHUNK_SIZE = 4096;
    const size_t ENCRYPTED_CHUNK_SIZE = CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES;

    QByteArray buffer(CHUNK_SIZE, 0);
    QByteArray encryptedChunk(ENCRYPTED_CHUNK_SIZE, 0);
    unsigned long long encryptedLen;

    while (!inputFile.atEnd())
    {
        qint64 bytesRead = inputFile.read(buffer.data(), CHUNK_SIZE);
        if (bytesRead <= 0)
            break;

        unsigned char tag = inputFile.atEnd() ? 
            crypto_secretstream_xchacha20poly1305_TAG_FINAL : 
            crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

        if (crypto_secretstream_xchacha20poly1305_push(
                &state,
                reinterpret_cast<unsigned char *>(encryptedChunk.data()), &encryptedLen,
                reinterpret_cast<const unsigned char *>(buffer.constData()), bytesRead,
                nullptr, 0, // no additional data
                tag) != 0)
        {
            SECURE_LOG(ERROR_LEVEL, "LibsodiumProvider", 
                "Secretstream encryption failed");
            return false;
        }

        outputFile.write(encryptedChunk.constData(), encryptedLen);
    }

    SECURE_LOG(INFO, "LibsodiumProvider", 
        "Secretstream encryption completed successfully");
    return true;
}

bool LibsodiumProvider::decryptWithSecretStream(QFile &inputFile, QFile &outputFile,
                                                const QByteArray &key, const QByteArray &nonce)
{
    crypto_secretstream_xchacha20poly1305_state state;

    if (crypto_secretstream_xchacha20poly1305_init_pull(
            &state,
            reinterpret_cast<const unsigned char *>(nonce.constData()),
            reinterpret_cast<const unsigned char *>(key.constData())) != 0)
    {
        SECURE_LOG(ERROR_LEVEL, "LibsodiumProvider", 
            "Failed to initialize secretstream decryption");
        return false;
    }

    const size_t CHUNK_SIZE = 4096;
    const size_t ENCRYPTED_CHUNK_SIZE = CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES;

    QByteArray encryptedChunk(ENCRYPTED_CHUNK_SIZE, 0);
    QByteArray decryptedChunk(CHUNK_SIZE, 0);
    unsigned long long decryptedLen;
    unsigned char tag;

    while (!inputFile.atEnd())
    {
        qint64 bytesRead = inputFile.read(encryptedChunk.data(), ENCRYPTED_CHUNK_SIZE);
        if (bytesRead <= 0)
            break;

        if (crypto_secretstream_xchacha20poly1305_pull(
                &state,
                reinterpret_cast<unsigned char *>(decryptedChunk.data()), &decryptedLen, &tag,
                reinterpret_cast<const unsigned char *>(encryptedChunk.constData()), bytesRead,
                nullptr, 0) != 0)
        {
            SECURE_LOG(ERROR_LEVEL, "LibsodiumProvider", 
                "Secretstream decryption failed (authentication error)");
            return false;
        }

        outputFile.write(decryptedChunk.constData(), decryptedLen);

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL)
        {
            break;
        }
    }

    SECURE_LOG(INFO, "LibsodiumProvider", 
        "Secretstream decryption completed successfully");
    return true;
}
