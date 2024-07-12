#ifndef ENCRYPTIONENGINE_H
#define ENCRYPTIONENGINE_H

#include <QString>
#include <QFile>
#include <QStringList>
#include <openssl/evp.h>
#include <openssl/hmac.h>

class EncryptionEngine
{
public:
    EncryptionEngine();
    ~EncryptionEngine();

    bool encryptFile(const QString& filePath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader);
    bool decryptFile(const QString& filePath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader);
    bool encryptFolder(const QString& folderPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader);
    bool decryptFolder(const QString& folderPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader);

    bool compressFolder(const QString& folderPath, const QString& outputFilePath);
    bool decompressFile(const QString& filePath, const QString& outputFolderPath);

    QByteArray getLastIv() const;

private:
    QByteArray lastIv; // Store the last used IV

    bool cryptOperation(const QString& inputPath, const QString& outputPath, const QString& password, const QString& algorithm, bool encrypt, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader);
    bool performStandardEncryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile);
    bool performStandardDecryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile);
    bool performAuthenticatedEncryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile);
    bool performAuthenticatedDecryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile);
    QByteArray deriveKey(const QByteArray& password, const QByteArray& salt);
    const EVP_CIPHER* getCipher(const QString& algorithm);
};

#endif // ENCRYPTIONENGINE_H
