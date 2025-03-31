// encryptionengine.h
#ifndef ENCRYPTIONENGINE_H
#define ENCRYPTIONENGINE_H

#include <QString>
#include <QFile>
#include <QStringList>
#include <vector>
#include <memory>
#include <cstring> // For memset

// Forward declarations for OpenSSL types
struct evp_cipher_st;
typedef struct evp_cipher_st EVP_CIPHER;
struct evp_cipher_ctx_st;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

#include "cryptoprovider.h"

class EncryptionEngine
{
public:
    EncryptionEngine();
    ~EncryptionEngine();

    // Provider selection methods
    void setProvider(const QString& providerName);
    QString currentProvider() const;
    QStringList availableProviders() const;

    bool encryptFile(const QString& filePath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths = QStringList());
    bool decryptFile(const QString& filePath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths = QStringList());
    bool encryptFolder(const QString& folderPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths = QStringList());
    bool decryptFolder(const QString& folderPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths = QStringList());

    bool compressFolder(const QString& folderPath, const QString& outputFilePath);
    bool decompressFolder(const QString& filePath, const QString& outputFolderPath);

    QByteArray getLastIv() const;

    bool isHardwareAccelerationSupported() const;

    QByteArray deriveKey(const QString& password, const QByteArray& salt, const QStringList& keyfilePaths, const QString& kdf, int iterations);
    QByteArray deriveKeyWithoutKeyfile(const QString &password, const QString &salt, const QString &kdf, int iterations, int keySize);

    // NEW: Secure salt and IV generation methods
    QByteArray generateSecureSalt(int size = 32);
    QByteArray generateSecureIV(int size = 16);

    const EVP_CIPHER* getCipher(const QString& algorithm);
    QStringList supportedCiphers() const;
    QStringList supportedKDFs() const;

private:
    QByteArray lastIv; // Store the last used IV
    
    // Vector to hold unique pointers to providers
    std::vector<std::unique_ptr<CryptoProvider>> m_providers;
    
    // Pointer to the current active provider
    CryptoProvider* m_currentProvider;
    QString m_currentProviderName;
    
    // Initialize all available providers
    void initializeProviders();

    // Key derivation helper methods
    QByteArray readKeyfile(const QString& keyfilePath);
    QByteArray performKeyDerivation(const QByteArray& passwordWithKeyfile, const QByteArray& salt, const QString& kdf, int iterations, int keySize);
    
    // NEW: Secure iteration calculation
    int calculateSecureIterations(const QString& kdf, int requestedIterations);
    
    // Encryption/decryption operations
    bool cryptOperation(const QString& inputPath, const QString& outputPath, const QString& password, const QString& algorithm, bool encrypt, const QString& kdf, int iterations, bool useHMAC, const QString& customHeader, const QStringList& keyfilePaths);
    
    // OpenSSL-specific encryption/decryption methods
    bool performStandardEncryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile);
    bool performStandardDecryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile);
    bool performAuthenticatedEncryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile);
    bool performAuthenticatedDecryption(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, const QByteArray& key, const QByteArray& iv, QFile& inputFile, QFile& outputFile);
    
    // Additional internal methods
    bool checkHardwareSupport();
    
    // Optional helper for retrieving a provider by name
    CryptoProvider* findProvider(const QString& providerName);
};

#endif // ENCRYPTIONENGINE_H
