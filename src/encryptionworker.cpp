#include "encryptionworker.h"
#include <QDebug>
#include <QElapsedTimer>
#include <QFileInfo>

EncryptionWorker::EncryptionWorker(QObject *parent)
    : QObject(parent)
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
    this->customHeader = customHeader;
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

    // Derive the key
    QString salt = "some_salt"; // You should generate a proper salt in a real application
    int keySize = 32; // Key size in bytes
    QByteArray key = engine.deriveKey(password, salt, kdf, iterations, keySize);

    if (key.isEmpty()) {
        emit finished(false, "Key derivation failed");
        return;
    }

    if (isFile) {
        if (encrypt) {
            success = engine.encryptFile(path, key, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths);
        } else {
            success = engine.decryptFile(path, key, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths);
        }
    } else {
        if (encrypt) {
            success = engine.encryptFolder(path, key, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths);
        } else {
            success = engine.decryptFolder(path, key, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths);
        }
    }

    double seconds = timer.elapsed() / 1000.0;
    emit estimatedTime(seconds);

    if (success) {
        emit progress(100);
        emit finished(true, QString());

        // Calculate the file size in MB
        double fileSizeMB = getFileSizeInBytes(path) / (1024.0 * 1024.0);
        double mbps = fileSizeMB / seconds;
        emit benchmarkResultReady(iterations, mbps, seconds * 1000, algorithm, kdf);

    } else {
        emit finished(false, "Encryption/Decryption failed");
    }
}

void EncryptionWorker::runBenchmark() {
    qDebug() << "Starting benchmark...";
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
    qDebug() << "Benchmark complete.";
}

void EncryptionWorker::benchmarkCipher(const QString &algorithm, const QString &kdf, bool useHardwareAcceleration) {
    if (kdf != "PBKDF2" && kdf != "Argon2" && kdf != "Scrypt") {
        qDebug() << "Skipping unknown KDF:" << kdf;
        return;
    }

    const int dataSize = 100 * 1024 * 1024; // 100 MB
    QByteArray testData(dataSize, 'A');
    QByteArray key(32, 'K');
    QByteArray iv(16, 'I');
    QByteArray salt(16, 'S');
    int iterations = 10;

    QElapsedTimer timer;
    timer.start();

    const EVP_CIPHER *cipher = engine.getCipher(algorithm);

    if (!cipher) {
        qDebug() << "Skipping" << algorithm << "- not supported";
        return;
    }

    key = engine.deriveKey("password", salt, kdf, iterations, key.size());
    if (key.isEmpty()) {
        qDebug() << "Key derivation failed for KDF:" << kdf;
        return;
    }

    // Perform encryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        qDebug() << "Failed to create EVP_CIPHER_CTX";
        return;
    }

    if (!EVP_EncryptInit_ex(ctx, cipher, nullptr,
                            reinterpret_cast<const unsigned char *>(key.data()),
                            reinterpret_cast<const unsigned char *>(iv.data()))) {
        qDebug() << "EVP_EncryptInit_ex failed";
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    QByteArray ciphertext(testData.size() + EVP_MAX_BLOCK_LENGTH, 0);
    int len;
    int ciphertextLen = 0;
    if (!EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char *>(ciphertext.data()), &len,
                           reinterpret_cast<const unsigned char *>(testData.data()), testData.size())) {
        qDebug() << "EVP_EncryptUpdate failed";
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertextLen += len;
    if (!EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(ciphertext.data()) + len, &len)) {
        qDebug() << "EVP_EncryptFinal_ex failed";
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    qint64 elapsed = timer.elapsed();
    double throughput = (dataSize / (1024.0 * 1024.0)) / (elapsed / 1000.0);

    emit benchmarkResultReady(iterations, throughput, elapsed, algorithm, kdf); // Emit the result
}
