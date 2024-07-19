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
