#include "encryptionworker.h"
#include <QDebug>
#include <QElapsedTimer>

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

void EncryptionWorker::process()
{
    QElapsedTimer timer;
    timer.start();

    bool success = false;
    QString errorMessage;

    if (isFile) {
        if (encrypt) {
            success = engine.encryptFile(path, password, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths);
        } else {
            success = engine.decryptFile(path, password, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths);
        }
    } else {
        if (encrypt) {
            success = engine.encryptFolder(path, password, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths);
        } else {
            success = engine.decryptFolder(path, password, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths);
        }
    }

    double seconds = timer.elapsed() / 1000.0;
    emit estimatedTime(seconds);

    if (success) {
        emit progress(100);
        emit finished(true, QString());
    } else {
        emit finished(false, "Encryption/Decryption failed");
    }
}
