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

    bool encryptFile(const QString& filePath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths = QStringList());
    bool decryptFile(const QString& filePath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths = QStringList());
    bool encryptFolder(const QString& folderPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths = QStringList());
    bool decryptFolder(const QString& folderPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths = QStringList());

    bool compressFolder(const QString& folderPath, const QString& outputFilePath);
    bool decompressFolder(const QString& filePath, const QString& outputFolderPath);

    QByteArray getLastIv() const;

    bool isHardwareAccelerationSupported() const;

    QByteArray deriveKey(const QString &password, const QString &salt, const QString &kdf, int iterations, int keySize);

    void runBenchmark();
    void benchmarkCipher(const QString& algorithm, const QString& kdf, bool useHardwareAcceleration);

    const EVP_CIPHER* getCipher(const QString& algorithm);  // Move to public
    const EVP_CIPHER* getHardwareAcceleratedCipher(const QString& algorithm);  // Move to public

private:
    QByteArray lastIv; // Store the last used IV
    bool m_aesNiSupported;

    bool cryptOperation(const QString& inputPath, const QString& outputPath, const QString& password, const QString& algorithm, bool encrypt, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths);
    bool performStandardEncryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile);
    bool performStandardDecryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile);
    bool performAuthenticatedEncryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile);
    bool performAuthenticatedDecryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile);
    QByteArray performKeyDerivation(const QByteArray& passwordWithKeyfile, const QByteArray& salt, const QString& kdf, int iterations, int keySize);

    QByteArray deriveKey(const QString& password, const QByteArray& salt, const QStringList& keyfilePaths, const QString& kdf, int iterations);
    QByteArray readKeyfile(const QString& keyfilePath);

    bool checkHardwareSupport();
};

#endif // ENCRYPTIONENGINE_H
