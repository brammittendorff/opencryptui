#include "encryptionengine.h"
#include <QFile>
#include <QDebug>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <sodium.h>

bool EncryptionEngine::cryptOperation(const QString& inputPath, const QString& outputPath, const QString& password, const QString& algorithm, bool encrypt, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths) {
    qDebug() << "Starting cryptOperation...";
    qDebug() << "Encrypt mode:" << encrypt;
    qDebug() << "Input file:" << inputPath;
    qDebug() << "Output file:" << outputPath;
    qDebug() << "Algorithm:" << algorithm;
    qDebug() << "KDF:" << kdf;
    qDebug() << "Iterations:" << iterations;
    qDebug() << "Use HMAC:" << useHMAC;

    QFile inputFile(inputPath);
    QFile outputFile(outputPath);

    if (!inputFile.open(QIODevice::ReadOnly)) {
        qDebug() << "Failed to open input file:" << inputPath;
        return false;
    }

    if (!outputFile.open(QIODevice::WriteOnly)) {
        qDebug() << "Failed to open output file:" << outputPath;
        return false;
    }

    const EVP_CIPHER* cipher = getCipher(algorithm);
    if (!cipher) {
        qDebug() << "Invalid algorithm:" << algorithm;
        return false;
    }

    int ivLength = EVP_CIPHER_iv_length(cipher);
    QByteArray iv(ivLength, 0);
    QByteArray salt(32, 0);

    if (encrypt) {
        RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), salt.size());
        RAND_bytes(reinterpret_cast<unsigned char*>(iv.data()), ivLength);
    } else {
        inputFile.seek(customHeader.size()); // Skip the custom header
        if (inputFile.read(salt.data(), salt.size()) != salt.size()) {
            qDebug() << "Failed to read salt from input file";
            inputFile.close();
            return false;
        }
    }

    qDebug() << "Deriving key...";
    QByteArray key = deriveKey(password, salt, keyfilePaths, kdf, iterations);

    if (key.isEmpty()) {
        sodium_munlock(key.data(), key.size());
        OPENSSL_cleanse(key.data(), key.size());
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
        outputFile.write(customHeader.toUtf8());
        outputFile.write(salt);
        outputFile.write(iv);
        success = useHMAC ? performAuthenticatedEncryption(ctx, cipher, key, iv, inputFile, outputFile)
                          : performStandardEncryption(ctx, cipher, key, iv, inputFile, outputFile);
    } else {
        QByteArray header(customHeader.size(), 0);
        if (inputFile.read(header.data(), customHeader.size()) != customHeader.size() || header != customHeader.toUtf8()) {
            qDebug() << "Failed to read or validate custom header";
            return false;
        }
        inputFile.seek(customHeader.size() + salt.size()); // Skip header and salt
        inputFile.read(iv.data(), iv.size());
        success = useHMAC ? performAuthenticatedDecryption(ctx, cipher, key, iv, inputFile, outputFile)
                          : performStandardDecryption(ctx, cipher, key, iv, inputFile, outputFile);
    }

    if (!success) {
        qDebug() << "Encryption/Decryption process failed.";
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
    // Initialize encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, cipher, nullptr, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data()))) {
        qDebug() << "EVP_EncryptInit_ex failed";
        return false;
    }

    QByteArray buffer(4096, 0);
    QByteArray outBuf(4096 + EVP_CIPHER_block_size(cipher), 0);
    int outLen = 0;
    
    while (!inputFile.atEnd()) {
        int inLen = inputFile.read(buffer.data(), buffer.size());
        if (1 != EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(outBuf.data()), &outLen, reinterpret_cast<const unsigned char*>(buffer.data()), inLen)) {
            qDebug() << "EVP_EncryptUpdate failed";
            return false;
        }
        outputFile.write(outBuf.data(), outLen);
    }

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(outBuf.data()), &outLen)) {
        qDebug() << "EVP_EncryptFinal_ex failed";
        return false;
    }
    outputFile.write(outBuf.data(), outLen);

    return true;
}

bool EncryptionEngine::performStandardDecryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile) {
    qDebug() << "Starting decryption process...";

    // Initialize the decryption operation
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
    int cipherMode = EVP_CIPHER_mode(cipher);
    QByteArray tag;
    bool isAuthenticatedMode = false;

    if (cipherMode == EVP_CIPH_GCM_MODE || cipherMode == EVP_CIPH_CCM_MODE || 
        EVP_CIPHER_nid(cipher) == NID_chacha20_poly1305) {
        tag.resize(16);
        isAuthenticatedMode = true;
        qDebug() << "Authenticated mode detected:" << EVP_CIPHER_name(cipher);
    } else {
        qDebug() << "Non-authenticated mode detected:" << EVP_CIPHER_name(cipher);
    }

    // Initialize encryption operation
    if (!EVP_EncryptInit_ex(ctx, cipher, nullptr, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data()))) {
        qDebug() << "EVP_EncryptInit_ex failed";
        return false;
    }

    QByteArray buffer(4096, 0);  // Input buffer
    QByteArray outputBuffer;  // Output buffer

    // Encrypt the data in chunks
    while (!inputFile.atEnd()) {
        qint64 bytesRead = inputFile.read(buffer.data(), buffer.size());
        if (bytesRead <= 0) break;

        outputBuffer.resize(bytesRead + EVP_CIPHER_block_size(cipher));
        int outLen;

        if (!EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(outputBuffer.data()), &outLen, 
                               reinterpret_cast<const unsigned char*>(buffer.constData()), bytesRead)) {
            qDebug() << "EVP_EncryptUpdate failed";
            return false;
        }

        outputFile.write(outputBuffer.constData(), outLen);
    }

    // Finalize the encryption
    outputBuffer.resize(EVP_CIPHER_block_size(cipher));
    int outLen;
    if (!EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(outputBuffer.data()), &outLen)) {
        qDebug() << "EVP_EncryptFinal_ex failed";
        return false;
    }

    if (outLen > 0) {
        outputFile.write(outputBuffer.constData(), outLen);
    }

    // Get the tag
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data())) {
        qDebug() << "EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_GET_TAG) failed";
        return false;
    }

    // Append the tag to the end of the file
    outputFile.write(tag);

    // At the end of the function
    qDebug() << "Encryption completed successfully";
    qDebug() << "Encrypted file size:" << outputFile.size() << "bytes";
    if (isAuthenticatedMode) {
        qDebug() << "Authentication tag:" << tag.toHex();
    }

    return true;
}

bool EncryptionEngine::performAuthenticatedDecryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile) {
    int cipherMode = EVP_CIPHER_mode(cipher);
    QByteArray tag;
    bool isAuthenticatedMode = false;

    if (cipherMode == EVP_CIPH_GCM_MODE || cipherMode == EVP_CIPH_CCM_MODE || 
        EVP_CIPHER_nid(cipher) == NID_chacha20_poly1305) {
        tag.resize(16);
        isAuthenticatedMode = true;
        qDebug() << "Authenticated mode detected:" << EVP_CIPHER_name(cipher);
    } else {
        qDebug() << "Non-authenticated mode detected:" << EVP_CIPHER_name(cipher);
    }

    // Read the entire encrypted content
    QByteArray encryptedContent = inputFile.readAll();

    // The last 16 bytes should be the tag
    if (encryptedContent.size() < 16) {
        qDebug() << "Encrypted content is too short";
        return false;
    }

    tag = encryptedContent.right(16);
    encryptedContent.chop(16);  // Remove the tag from the encrypted content

    qDebug() << "Tag read for decryption (Hex):" << tag.toHex();

    // Initialize decryption operation
    if (!EVP_DecryptInit_ex(ctx, cipher, nullptr, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data()))) {
        qDebug() << "EVP_DecryptInit_ex failed";
        return false;
    }

    QByteArray outputBuffer(encryptedContent.size() + EVP_CIPHER_block_size(cipher), 0);
    int outLen;

    // Decrypt the data
    if (!EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(outputBuffer.data()), &outLen, 
                           reinterpret_cast<const unsigned char*>(encryptedContent.constData()), encryptedContent.size())) {
        qDebug() << "EVP_DecryptUpdate failed";
        return false;
    }

    // Set the expected tag
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data())) {
        qDebug() << "EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_TAG) failed";
        return false;
    }

    int tmpLen;
    // Finalize the decryption and check the tag
    if (!EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(outputBuffer.data()) + outLen, &tmpLen)) {
        qDebug() << "EVP_DecryptFinal_ex failed - authentication failure";
        return false;
    }

    outLen += tmpLen;
    outputFile.write(outputBuffer.constData(), outLen);

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
