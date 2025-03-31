// cryptoprovider.h
#ifndef CRYPTOPROVIDER_H
#define CRYPTOPROVIDER_H

#include <QString>
#include <QStringList>
#include <QByteArray>
#include <QFile>

// Forward declaration for OpenSSL types
struct evp_cipher_st;
typedef struct evp_cipher_st EVP_CIPHER;
struct evp_cipher_ctx_st;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

// Abstract interface for crypto providers
class CryptoProvider
{
public:
    virtual ~CryptoProvider() {}

    // Key derivation
    virtual QByteArray deriveKey(const QByteArray &password, const QByteArray &salt,
                                 const QString &kdf, int iterations, int keySize) = 0;

    // Encryption/decryption operations
    virtual bool encrypt(QFile &inputFile, QFile &outputFile, const QByteArray &key,
                         const QByteArray &iv, const QString &algorithm, bool useAuthentication) = 0;

    virtual bool decrypt(QFile &inputFile, QFile &outputFile, const QByteArray &key,
                         const QByteArray &iv, const QString &algorithm, bool useAuthentication) = 0;

    // Utility functions
    virtual QByteArray generateRandomBytes(int size) = 0;
    virtual bool isHardwareAccelerationSupported() = 0;

    // Information functions
    virtual QStringList supportedCiphers() = 0;
    virtual QStringList supportedKDFs() = 0;

    // Provider name
    virtual QString providerName() const = 0;
};

// OpenSSL implementation
class OpenSSLProvider : public CryptoProvider
{
public:
    OpenSSLProvider();
    ~OpenSSLProvider();

    QByteArray deriveKey(const QByteArray &password, const QByteArray &salt,
                         const QString &kdf, int iterations, int keySize) override;

    bool encrypt(QFile &inputFile, QFile &outputFile, const QByteArray &key,
                 const QByteArray &iv, const QString &algorithm, bool useAuthentication) override;

    bool decrypt(QFile &inputFile, QFile &outputFile, const QByteArray &key,
                 const QByteArray &iv, const QString &algorithm, bool useAuthentication) override;

    QByteArray generateRandomBytes(int size) override;
    bool isHardwareAccelerationSupported() override;

    QStringList supportedCiphers() override;
    QStringList supportedKDFs() override;

    QString providerName() const override { return "OpenSSL"; }

private:
    // OpenSSL specific members and helper functions
    const EVP_CIPHER *getCipher(const QString &algorithm);
    bool checkHardwareSupport();
    bool m_aesNiSupported;

    // Add these method declarations
    bool performStandardEncryption(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                                   const QByteArray &key, const QByteArray &iv,
                                   QFile &inputFile, QFile &outputFile);

    bool performStandardDecryption(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                                   const QByteArray &key, const QByteArray &iv,
                                   QFile &inputFile, QFile &outputFile);

    bool performAuthenticatedEncryption(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                                        const QByteArray &key, const QByteArray &iv,
                                        QFile &inputFile, QFile &outputFile);

    bool performAuthenticatedDecryption(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                                        const QByteArray &key, const QByteArray &iv,
                                        QFile &inputFile, QFile &outputFile);
};

// Libsodium implementation
class LibsodiumProvider : public CryptoProvider
{
public:
    LibsodiumProvider();
    ~LibsodiumProvider();

    QByteArray deriveKey(const QByteArray &password, const QByteArray &salt,
                         const QString &kdf, int iterations, int keySize) override;

    bool encrypt(QFile &inputFile, QFile &outputFile, const QByteArray &key,
                 const QByteArray &iv, const QString &algorithm, bool useAuthentication) override;

    bool decrypt(QFile &inputFile, QFile &outputFile, const QByteArray &key,
                 const QByteArray &iv, const QString &algorithm, bool useAuthentication) override;

    QByteArray generateRandomBytes(int size) override;
    bool isHardwareAccelerationSupported() override;

    QStringList supportedCiphers() override;
    QStringList supportedKDFs() override;

    QString providerName() const override { return "libsodium"; }

private:
    bool encryptWithXChaCha20Poly1305(QFile &inputFile, QFile &outputFile, 
                                      const QByteArray &key, const QByteArray &nonce);
    bool decryptWithXChaCha20Poly1305(QFile &inputFile, QFile &outputFile, 
                                      const QByteArray &key, const QByteArray &nonce);
    bool encryptWithSecretStream(QFile &inputFile, QFile &outputFile, 
                                 const QByteArray &key, const QByteArray &nonce);
    bool decryptWithSecretStream(QFile &inputFile, QFile &outputFile, 
                                 const QByteArray &key, const QByteArray &nonce);
};

// Argon2 specialized provider (primarily for KDFs)
class Argon2Provider : public CryptoProvider
{
public:
    Argon2Provider();
    ~Argon2Provider();

    QByteArray deriveKey(const QByteArray &password, const QByteArray &salt,
                         const QString &kdf, int iterations, int keySize) override;

    // Since Argon2 is primarily a KDF library, we'll delegate encryption to OpenSSL
    bool encrypt(QFile &inputFile, QFile &outputFile, const QByteArray &key,
                 const QByteArray &iv, const QString &algorithm, bool useAuthentication) override;

    bool decrypt(QFile &inputFile, QFile &outputFile, const QByteArray &key,
                 const QByteArray &iv, const QString &algorithm, bool useAuthentication) override;

    QByteArray generateRandomBytes(int size) override;
    bool isHardwareAccelerationSupported() override;

    QStringList supportedCiphers() override;
    QStringList supportedKDFs() override;

    QString providerName() const override { return "Argon2"; }

private:
    // We'll use OpenSSL for the non-KDF operations
    OpenSSLProvider m_opensslProvider;
};

#endif // CRYPTOPROVIDER_H