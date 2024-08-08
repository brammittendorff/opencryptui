#include "encryptionengine.h"
#include <QFile>
#include <QDebug>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <sodium.h> // Ensure Sodium library is included

bool EncryptionEngine::cryptOperation(const QString& inputPath, const QString& outputPath, const QString& password, const QString& algorithm, bool encrypt, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths) {
    QFile inputFile(inputPath);
    QFile outputFile(outputPath);

    if (!inputFile.open(QIODevice::ReadOnly)) {
        qDebug() << "Failed to open input file";
        return false;
    }

    if (!outputFile.open(QIODevice::WriteOnly)) {
        qDebug() << "Failed to open output file";
        return false;
    }

    const EVP_CIPHER* cipher = getCipher(algorithm);
    if (!cipher) {
        qDebug() << "Invalid algorithm";
        return false;
    }

    int ivLength = EVP_CIPHER_iv_length(cipher);
    QByteArray iv(ivLength, 0);
    QByteArray salt(16, 0);

    if (encrypt) {
        RAND_bytes(reinterpret_cast<unsigned char*>(iv.data()), ivLength);
        RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), salt.size());
        outputFile.write(customHeader.toUtf8());
        outputFile.write(salt);
        outputFile.write(iv);
        lastIv = iv; // Store the last used IV
    } else {
        QByteArray header(customHeader.size(), 0);
        if (inputFile.read(header.data(), customHeader.size()) != customHeader.size() || header != customHeader.toUtf8()) {
            qDebug() << "Failed to read or validate custom header";
            return false;
        }
        inputFile.read(salt.data(), salt.size());
        inputFile.read(iv.data(), iv.size());
        lastIv = iv; // Store the last used IV
    }

    QByteArray key = deriveKey(password, salt, keyfilePaths, kdf, iterations);

    if (key.isEmpty()) {
        return false;
    }

    if (sodium_mlock(key.data(), key.size()) != 0) {
        qDebug() << "Failed to lock key in memory";
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        qDebug() << "Failed to create EVP_CIPHER_CTX";
        sodium_munlock(key.data(), key.size());
        return false;
    }

    bool success = false;
    if (encrypt) {
        success = useHMAC ? performAuthenticatedEncryption(ctx, cipher, key, iv, inputFile, outputFile)
                          : performStandardEncryption(ctx, cipher, key, iv, inputFile, outputFile);
    } else {
        success = useHMAC ? performAuthenticatedDecryption(ctx, cipher, key, iv, inputFile, outputFile)
                          : performStandardDecryption(ctx, cipher, key, iv, inputFile, outputFile);
    }

    EVP_CIPHER_CTX_free(ctx);
    inputFile.close();
    outputFile.close();

    sodium_munlock(key.data(), key.size());
    OPENSSL_cleanse(key.data(), key.size());
    OPENSSL_cleanse(iv.data(), iv.size());
    OPENSSL_cleanse(salt.data(), salt.size());

    return success;
}

bool EncryptionEngine::performStandardEncryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile) {
    if (!EVP_EncryptInit_ex(ctx, cipher, nullptr, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data()))) {
        qDebug() << "EVP_EncryptInit_ex failed";
        return false;
    }

    QByteArray buffer(4096, 0);
    QByteArray outputBuffer(4096 + EVP_CIPHER_block_size(cipher), 0);
    int outLen;

    while (!inputFile.atEnd()) {
        int inLen = inputFile.read(buffer.data(), buffer.size());
        if (!EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(outputBuffer.data()), &outLen, reinterpret_cast<unsigned char*>(buffer.data()), inLen)) {
            qDebug() << "EVP_EncryptUpdate failed";
            return false;
        }
        outputFile.write(outputBuffer.data(), outLen);
    }

    if (!EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(outputBuffer.data()), &outLen)) {
        qDebug() << "EVP_EncryptFinal_ex failed";
        return false;
    }
    outputFile.write(outputBuffer.data(), outLen);

    return true;
}

bool EncryptionEngine::performStandardDecryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile) {
    if (!EVP_DecryptInit_ex(ctx, cipher, nullptr, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data()))) {
        qDebug() << "EVP_DecryptInit_ex failed";
        return false;
    }

    QByteArray buffer(4096, 0);
    QByteArray outputBuffer(4096 + EVP_CIPHER_block_size(cipher), 0);
    int outLen;

    while (!inputFile.atEnd()) {
        int inLen = inputFile.read(buffer.data(), buffer.size());
        if (!EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(outputBuffer.data()), &outLen, reinterpret_cast<unsigned char*>(buffer.data()), inLen)) {
            qDebug() << "EVP_DecryptUpdate failed";
            return false;
        }
        outputFile.write(outputBuffer.data(), outLen);
    }

    if (!EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(outputBuffer.data()), &outLen)) {
        qDebug() << "EVP_DecryptFinal_ex failed";
        return false;
    }
    outputFile.write(outputBuffer.data(), outLen);

    return true;
}

bool EncryptionEngine::performAuthenticatedEncryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile) {
    QByteArray tag(16, 0);
    if (!EVP_EncryptInit_ex(ctx, cipher, nullptr, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data()))) {
        qDebug() << "EVP_EncryptInit_ex failed";
        return false;
    }

    QByteArray buffer(4096, 0);
    QByteArray outputBuffer(4096 + EVP_CIPHER_block_size(cipher), 0);
    int outLen;

    while (!inputFile.atEnd()) {
        int inLen = inputFile.read(buffer.data(), buffer.size());
        if (!EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(outputBuffer.data()), &outLen, reinterpret_cast<unsigned char*>(buffer.data()), inLen)) {
            qDebug() << "EVP_EncryptUpdate failed";
            return false;
        }
        outputFile.write(outputBuffer.data(), outLen);
    }

    if (!EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(outputBuffer.data()), &outLen)) {
        qDebug() << "EVP_EncryptFinal_ex failed";
        return false;
    }
    outputFile.write(outputBuffer.data(), outLen);

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data())) {
        qDebug() << "EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_GET_TAG) failed";
        return false;
    }
    outputFile.write(tag);

    return true;
}

bool EncryptionEngine::performAuthenticatedDecryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile) {
    QByteArray tag(16, 0);
    inputFile.seek(inputFile.size() - tag.size());
    inputFile.read(tag.data(), tag.size());
    inputFile.seek(0);

    if (!EVP_DecryptInit_ex(ctx, cipher, nullptr, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data()))) {
        qDebug() << "EVP_DecryptInit_ex failed";
        return false;
    }

    QByteArray buffer(4096, 0);
    QByteArray outputBuffer(4096 + EVP_CIPHER_block_size(cipher), 0);
    int outLen;

    while (inputFile.pos() < inputFile.size() - tag.size()) {
        int inLen = inputFile.read(buffer.data(), buffer.size());
        if (!EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(outputBuffer.data()), &outLen, reinterpret_cast<unsigned char*>(buffer.data()), inLen)) {
            qDebug() << "EVP_DecryptUpdate failed";
            return false;
        }
        outputFile.write(outputBuffer.data(), outLen);
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data())) {
        qDebug() << "EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_TAG) failed";
        return false;
    }

    if (!EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(outputBuffer.data()), &outLen)) {
        qDebug() << "EVP_DecryptFinal_ex failed";
        return false;
    }
    outputFile.write(outputBuffer.data(), outLen);

    return true;
}

const EVP_CIPHER* EncryptionEngine::getCipher(const QString& algorithm) {
    if (algorithm == "AES-256-GCM") return EVP_aes_256_gcm();
    if (algorithm == "ChaCha20-Poly1305") return EVP_chacha20_poly1305();
    if (algorithm == "AES-256-CTR") return EVP_aes_256_ctr();
    if (algorithm == "AES-256-CBC") return EVP_aes_256_cbc();
    if (algorithm == "AES-128-GCM") return EVP_aes_128_gcm();
    if (algorithm == "AES-128-CTR") return EVP_aes_128_ctr();
    if (algorithm == "AES-192-GCM") return EVP_aes_192_gcm();
    if (algorithm == "AES-192-CTR") return EVP_aes_192_ctr();
    if (algorithm == "AES-128-CBC") return EVP_aes_128_cbc();
    if (algorithm == "AES-192-CBC") return EVP_aes_192_cbc();
    if (algorithm == "Camellia-256-CBC") return EVP_camellia_256_cbc();
    if (algorithm == "Camellia-128-CBC") return EVP_camellia_128_cbc();

    return nullptr; // Ensure this correctly returns nullptr for unsupported ciphers
}
