#include "encryptionengine.h"
#include <QDir>
#include <QFile>
#include <QDebug>
#include <QProcess>
#include <QByteArray>
#include <QFileInfo>
#include <QDirIterator>
#include <QElapsedTimer>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <argon2.h>
#include <sodium.h>
#include <cpuid.h>

EncryptionEngine::EncryptionEngine() {
    OpenSSL_add_all_algorithms();
    if (sodium_init() < 0) {
        qDebug() << "Failed to initialize libsodium";
        throw std::runtime_error("Failed to initialize libsodium");
    }
    m_aesNiSupported = checkHardwareSupport();
    if (m_aesNiSupported) {
        qDebug() << "AES-NI hardware acceleration is supported";
    } else {
        qDebug() << "AES-NI hardware acceleration is not supported";
    }
}

bool EncryptionEngine::isHardwareAccelerationSupported() const
{
    return m_aesNiSupported;
}

EncryptionEngine::~EncryptionEngine() {
    EVP_cleanup();
}

QByteArray EncryptionEngine::getLastIv() const {
    return lastIv;
}

bool EncryptionEngine::compressFolder(const QString& folderPath, const QString& outputFilePath) {
    QProcess process;
    process.start("tar", QStringList() << "-czf" << outputFilePath << folderPath);
    process.waitForFinished(-1);

    return process.exitCode() == 0;
}

bool EncryptionEngine::decompressFile(const QString& filePath, const QString& outputFolderPath) {
    QProcess process;
    process.start("tar", QStringList() << "-xzf" << filePath << "-C" << outputFolderPath);
    process.waitForFinished(-1);

    return process.exitCode() == 0;
}

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

bool EncryptionEngine::encryptFile(const QString& filePath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths) {
    QString outputPath = filePath + ".enc";
    return cryptOperation(filePath, outputPath, password, algorithm, true, kdf, iterations, useHMAC, customHeader, keyfilePaths);
}

bool EncryptionEngine::decryptFile(const QString& filePath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths) {
    QString outputPath = filePath;
    outputPath.chop(4); // Remove ".enc"
    bool success = cryptOperation(filePath, outputPath, password, algorithm, false, kdf, iterations, useHMAC, customHeader, keyfilePaths);
    if (!success) {
        return false;
    }
    return true;
}

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

    // Lock the key in memory to prevent it from being swapped out
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
        if (!EVP_EncryptInit_ex(ctx, cipher, nullptr, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data()))) {
            qDebug() << "EVP_EncryptInit_ex failed";
            sodium_munlock(key.data(), key.size());
            return false;
        }

        QByteArray buffer(4096, 0);
        QByteArray outputBuffer(4096 + EVP_CIPHER_block_size(cipher), 0);
        int outLen;

        while (!inputFile.atEnd()) {
            int inLen = inputFile.read(buffer.data(), buffer.size());
            if (!EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(outputBuffer.data()), &outLen, reinterpret_cast<unsigned char*>(buffer.data()), inLen)) {
                qDebug() << "EVP_EncryptUpdate failed";
                sodium_munlock(key.data(), key.size());
                return false;
            }
            outputFile.write(outputBuffer.data(), outLen);
        }

        if (!EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(outputBuffer.data()), &outLen)) {
            qDebug() << "EVP_EncryptFinal_ex failed";
            sodium_munlock(key.data(), key.size());
            return false;
        }
        outputFile.write(outputBuffer.data(), outLen);

        success = true;
    } else {
        if (!EVP_DecryptInit_ex(ctx, cipher, nullptr, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data()))) {
            qDebug() << "EVP_DecryptInit_ex failed";
            sodium_munlock(key.data(), key.size());
            return false;
        }

        QByteArray buffer(4096, 0);
        QByteArray outputBuffer(4096 + EVP_CIPHER_block_size(cipher), 0);
        int outLen;

        while (!inputFile.atEnd()) {
            int inLen = inputFile.read(buffer.data(), buffer.size());
            if (!EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(outputBuffer.data()), &outLen, reinterpret_cast<unsigned char*>(buffer.data()), inLen)) {
                qDebug() << "EVP_DecryptUpdate failed";
                sodium_munlock(key.data(), key.size());
                return false;
            }
            outputFile.write(outputBuffer.data(), outLen);
        }

        if (!EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(outputBuffer.data()), &outLen)) {
            qDebug() << "EVP_DecryptFinal_ex failed";
            sodium_munlock(key.data(), key.size());
            return false;
        }
        outputFile.write(outputBuffer.data(), outLen);

        success = true;
    }

    EVP_CIPHER_CTX_free(ctx);
    inputFile.close();
    outputFile.close();

    // Unlock the key from memory
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
    const EVP_CIPHER* hardwareCipher = getHardwareAcceleratedCipher(algorithm);
    if (hardwareCipher) {
        return hardwareCipher;
    }

    if (algorithm == "AES-256-CBC") return EVP_aes_256_cbc();
    if (algorithm == "AES-256-GCM") return EVP_aes_256_gcm();
    if (algorithm == "AES-256-CTR") return EVP_aes_256_ctr();
    if (algorithm == "ChaCha20-Poly1305") return EVP_chacha20_poly1305();
    if (algorithm == "Twofish") return EVP_get_cipherbyname("twofish");
    if (algorithm == "Serpent") return EVP_get_cipherbyname("serpent");
    if (algorithm == "Blowfish") return EVP_bf_cbc();
    if (algorithm == "Camellia-256-CBC") return EVP_camellia_256_cbc();
    if (algorithm == "AES-128-CBC") return EVP_aes_128_cbc();

    return nullptr;
}

bool EncryptionEngine::encryptFolder(const QString& folderPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths) {
    QString compressedFilePath = folderPath + ".tar.gz";
    if (!compressFolder(folderPath, compressedFilePath)) {
        return false;
    }

    bool success = encryptFile(compressedFilePath, password, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths);

    return success;
}

bool EncryptionEngine::decryptFolder(const QString& folderPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths) {
    QString encryptedFilePath = folderPath + ".enc";
    QString compressedFilePath = folderPath + ".tar.gz";

    if (!decryptFile(encryptedFilePath, password, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths)) {
        return false;
    }

    bool success = decompressFile(compressedFilePath, folderPath);

    return success;
}

bool EncryptionEngine::checkHardwareSupport() {
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx & bit_AES) != 0;
    }
    return false;
}

const EVP_CIPHER* EncryptionEngine::getHardwareAcceleratedCipher(const QString& algorithm) {
    if (m_aesNiSupported) {
        // AES-NI is supported, return hardware-accelerated versions of AES ciphers
        if (algorithm == "AES-256-CBC") {
            return EVP_aes_256_cbc();
        } else if (algorithm == "AES-256-GCM") {
            return EVP_aes_256_gcm();
        } else if (algorithm == "AES-256-CTR") {
            return EVP_aes_256_ctr();
        } else if (algorithm == "AES-128-CBC") {
            return EVP_aes_128_cbc();
        } else if (algorithm == "AES-128-GCM") {
            return EVP_aes_128_gcm();
        } else if (algorithm == "AES-128-CTR") {
            return EVP_aes_128_ctr();
        } else if (algorithm == "AES-192-CBC") {
            return EVP_aes_192_cbc();
        } else if (algorithm == "AES-192-GCM") {
            return EVP_aes_192_gcm();
        } else if (algorithm == "AES-192-CTR") {
            return EVP_aes_192_ctr();
        }
    }

    // For non-AES algorithms or if AES-NI is not supported, return nullptr
    // This will cause the main getCipher function to fall back to non-accelerated versions
    return nullptr;
}

void EncryptionEngine::runBenchmark() {
    QStringList algorithms = {
        "AES-256-CBC", "AES-256-GCM", "AES-256-CTR",
        "AES-192-CBC", "AES-192-GCM", "AES-192-CTR",
        "AES-128-CBC", "AES-128-GCM", "AES-128-CTR",
        "ChaCha20-Poly1305", "Twofish", "Serpent",
        "Blowfish", "Camellia-256-CBC"
    };

    qDebug() << "Starting benchmark...";
    for (const auto& algo : algorithms) {
        benchmarkCipher(algo, true);
        if (algo.startsWith("AES")) {
            benchmarkCipher(algo, false);
        }
    }
    qDebug() << "Benchmark complete.";
}

void EncryptionEngine::benchmarkCipher(const QString& algorithm, bool useHardwareAcceleration) {
    const int dataSize = 100 * 1024 * 1024; // 100 MB
    QByteArray testData(dataSize, 'A');
    QByteArray key(32, 'K');
    QByteArray iv(16, 'I');

    QElapsedTimer timer;
    timer.start();

    const EVP_CIPHER* cipher = useHardwareAcceleration ? 
                               getHardwareAcceleratedCipher(algorithm) : 
                               getCipher(algorithm);
    
    if (!cipher) {
        qDebug() << "Skipping" << algorithm << "- not supported";
        return;
    }

    // Perform encryption
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, nullptr, 
                       reinterpret_cast<const unsigned char*>(key.data()), 
                       reinterpret_cast<const unsigned char*>(iv.data()));

    QByteArray ciphertext(testData.size() + EVP_MAX_BLOCK_LENGTH, 0);
    int len;
    int ciphertextLen = 0;
    EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()), &len, 
                      reinterpret_cast<const unsigned char*>(testData.data()), testData.size());
    ciphertextLen += len;
    EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()) + len, &len);
    ciphertextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    qint64 elapsed = timer.elapsed();
    double throughput = (dataSize / (1024.0 * 1024.0)) / (elapsed / 1000.0);

    qDebug() << "Algorithm:" << algorithm 
             << "Time:" << elapsed << "ms" 
             << "Throughput:" << throughput << "MB/s"
             << (useHardwareAcceleration ? "(Hardware Accelerated)" : "(Software)");
}
