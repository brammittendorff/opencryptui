// encryptionengine.h
#ifndef ENCRYPTIONENGINE_H
#define ENCRYPTIONENGINE_H

#include <QString>
#include <QFile>
#include <QStringList>
#include <QDateTime>
#include <QMutex>
#include <vector>
#include <memory>
#include <cstring> // For memset
#include <cmath> // For std::abs

// Forward declarations for OpenSSL types
struct evp_cipher_st;
typedef struct evp_cipher_st EVP_CIPHER;
struct evp_cipher_ctx_st;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

#include "cryptoprovider.h"
#include "encryptionengine_diskops.h"

class EncryptionEngine
{
public:
    // Structure to hold entropy test results
    struct EntropyTestResult {
        bool passed;
        QString testName;
        QString details;
        double bitFrequency = 0.5;
        double runsValue = 1.0;
        double serialCorrelation = 0.0;
    };
    
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
    
    // Secure deletion methods
    bool secureDeleteFile(const QString& filePath, int passes = 3);
    bool secureDeletePlaintext(const QString& plaintextFilePath);
    bool scrubFileInode(const QString& filePath);
    
    // Security policy methods
    bool verifyOutputPathSecurity(const QString& filePath);
    bool checkAndFixFilePermissions(const QString& filePath, QFileDevice::Permissions desiredPermissions);
    
    // Disk encryption methods
    bool encryptDisk(const QString& diskPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QStringList& keyfilePaths = QStringList());
    bool decryptDisk(const QString& diskPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QStringList& keyfilePaths = QStringList());
    
    // Hidden volume support - encrypt/decrypt specific section of disk
    bool encryptDiskSection(const QString& diskPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QStringList& keyfilePaths, qint64 startOffset, qint64 sectionSize);
    bool decryptDiskSection(const QString& diskPath, const QString& password, const QString& algorithm, const QString& kdf, int iterations, bool useHMAC, const QStringList& keyfilePaths, qint64 startOffset, qint64 sectionSize);

    bool compressFolder(const QString& folderPath, const QString& outputFilePath);
    bool decompressFolder(const QString& filePath, const QString& outputFolderPath);

    // Removed getLastIv method for security reasons

    bool isHardwareAccelerationSupported() const;

    QByteArray deriveKey(const QString& password, const QByteArray& salt, const QStringList& keyfilePaths, const QString& kdf, int iterations);
    QByteArray deriveKeyWithoutKeyfile(const QString &password, const QString &salt, const QString &kdf, int iterations, int keySize);

    // Secure random number generation methods
    QByteArray generateSecureSalt(int size = 32);
    QByteArray generateSecureIV(int size = 16);
    QByteArray generateSecureRandomBytes(int size, bool isSecurityCritical = true);
    
    // Entropy health monitoring methods
    QString getEntropyHealthStatus() const;
    int getEntropyHealthScore() const;
    bool isHardwareRngAvailable() const;
    int getBitDistribution() const; 
    int getEntropyEstimate() const;
    QDateTime getLastEntropyTestTime() const;
    EntropyTestResult performEntropyTest(int sampleSize = 1024);

    const EVP_CIPHER* getCipher(const QString& algorithm);
    QStringList supportedCiphers() const;
    QStringList supportedKDFs() const;

private:
    // Removed lastIv storage for security reasons
    
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
    
    // Tamper-evidence and digital signature methods
    QByteArray generateDigitalSignature(QFile& inputFile, const QByteArray& key);
    void appendSignature(QFile& outputFile, const QByteArray& signature);
    bool verifySignature(QFile& inputFile, const QByteArray& key, QByteArray& storedSignature);
    quint32 calculateCRC32(const QByteArray& data);
    
    // Hardware RNG support
    bool checkHardwareRngSupport();
    bool getHardwareRandomBytes(char* buffer, int size);
#ifdef __x86_64__
    bool getRdrandBytes(char* buffer, int size);
#endif

    // Entropy testing methods
    EntropyTestResult testEntropyQuality(const QByteArray& data);
    double testFrequency(const QByteArray& data);
    double testRuns(const QByteArray& data);
    double testSerialCorrelation(const QByteArray& data);
    
    // Entropy health monitoring
    void updateEntropyHealthMetrics(const EntropyTestResult& result);
    void hashWhitenData(const QByteArray& input, QByteArray& output);
    
    // Entropy health status metrics
    mutable QMutex m_entropyMetricsMutex;
    QString m_entropyHealthStatus = "Unknown";
    int m_entropyHealthScore = 0; 
    bool m_hardwareRngAvailable = false;
    int m_bitDistribution = 50;
    int m_entropyEstimate = 0;
    QDateTime m_lastEntropyTestTime;
};

#endif // ENCRYPTIONENGINE_H
