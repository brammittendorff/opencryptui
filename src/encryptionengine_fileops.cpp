#include "encryptionengine.h"
#include <QFile>
#include <QProcess>
#include <QDebug>
#include <openssl/rand.h>

bool EncryptionEngine::compressFolder(const QString& folderPath, const QString& outputFilePath) {
    QProcess process;
    process.start("tar", QStringList() << "-czf" << outputFilePath << folderPath);
    process.waitForFinished(-1);
    return process.exitCode() == 0;
}

bool EncryptionEngine::decompressFolder(const QString& filePath, const QString& outputFolderPath) {
    QProcess process;
    process.start("tar", QStringList() << "-xzf" << filePath << "-C" << outputFolderPath);
    process.waitForFinished(-1);
    return process.exitCode() == 0;
}

bool EncryptionEngine::encryptFile(const QString& filePath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths) {
    QString outputPath = filePath + ".enc";
    return cryptOperation(filePath, outputPath, password, algorithm, true, kdf, iterations, useHMAC, customHeader, keyfilePaths);
}

bool EncryptionEngine::decryptFile(const QString& filePath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths) {
    QString outputPath = filePath;
    outputPath.chop(4); // Remove ".enc"
    return cryptOperation(filePath, outputPath, password, algorithm, false, kdf, iterations, useHMAC, customHeader, keyfilePaths);
}

bool EncryptionEngine::encryptFolder(const QString& folderPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths) {
    QString compressedFilePath = folderPath + ".tar.gz";
    if (!compressFolder(folderPath, compressedFilePath)) {
        return false;
    }
    return encryptFile(compressedFilePath, password, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths);
}

bool EncryptionEngine::decryptFolder(const QString& folderPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths) {
    QString encryptedFilePath = folderPath + ".enc";
    QString compressedFilePath = folderPath + ".tar.gz";
    if (!decryptFile(encryptedFilePath, password, algorithm, kdf, iterations, useHMAC, customHeader, keyfilePaths)) {
        return false;
    }
    return decompressFolder(compressedFilePath, folderPath);
}