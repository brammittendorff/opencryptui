#include "encryptionengine.h"
#include <QDebug>
#include <QElapsedTimer>
#include <openssl/evp.h>

void EncryptionEngine::runBenchmark() {
    QStringList algorithms = {
        "AES-256-CBC", "AES-256-GCM", "AES-256-CTR",
        "AES-192-CBC", "AES-192-GCM", "AES-192-CTR",
        "AES-128-CBC", "AES-128-GCM", "AES-128-CTR",
        "ChaCha20-Poly1305", "Twofish", "Serpent",
        "Blowfish", "Camellia-256-CBC"
    };

    QStringList kdfs = {"PBKDF2", "Argon2", "Scrypt"};

    qDebug() << "Starting benchmark...";
    for (const auto& algo : algorithms) {
        for (const auto& kdf : kdfs) {
            benchmarkCipher(algo, kdf, true);
            if (algo.startsWith("AES")) {
                benchmarkCipher(algo, kdf, false);
            }
        }
    }
    qDebug() << "Benchmark complete.";
}

void EncryptionEngine::benchmarkCipher(const QString& algorithm, const QString& kdf, bool useHardwareAcceleration) {
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

    const EVP_CIPHER* cipher = useHardwareAcceleration ? 
                               getHardwareAcceleratedCipher(algorithm) : 
                               getCipher(algorithm);

    if (!cipher) {
        qDebug() << "Skipping" << algorithm << "- not supported";
        return;
    }

    key = deriveKey("password", salt, kdf, iterations, key.size());
    if (key.isEmpty()) {
        qDebug() << "Key derivation failed for KDF:" << kdf;
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

    qDebug() << QString("Algorithm: %1 KDF: %2 Time: %3 ms Throughput: %4 MB/s %5")
                .arg(algorithm)
                .arg(kdf)
                .arg(elapsed)
                .arg(throughput, 0, 'f', 2)
                .arg(useHardwareAcceleration ? "(Hardware Accelerated)" : "(Software)");
}
