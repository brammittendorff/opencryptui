#include "cryptoprovider.h"
#include "logging/secure_logger.h"
#include <argon2.h>
#include <openssl/rand.h>
#include <sodium.h>
#ifdef Q_OS_LINUX
#include <sys/sysinfo.h>
#elif defined(Q_OS_MAC) || defined(Q_OS_DARWIN)
#include <sys/types.h>
#include <sys/sysctl.h>
#elif defined(Q_OS_WIN)
#include <windows.h>
#endif
#include <algorithm>
#include <QSysInfo>

Argon2Provider::Argon2Provider()
{
    SECURE_LOG(INFO, "Argon2Provider", "Argon2 provider initialized");
}

Argon2Provider::~Argon2Provider()
{
    // No explicit cleanup needed
}

QByteArray Argon2Provider::deriveKey(const QByteArray &password, const QByteArray &salt,
                                     const QString &kdf, int iterations, int keySize)
{
    // Initialize a QByteArray to hold the derived key
    QByteArray key(keySize, 0);
    bool success = false;

    if (kdf == "Argon2")
    {
        // Determine memory cost - use government-level defaults
        // For high-security government applications, use much higher memory cost
        uint32_t memoryKb = 1 << 20; // 1 GB for government-grade security
        
        // Dynamic scaling based on available RAM - platform specific implementation
        uint64_t totalMemoryBytes = 0;
        
#ifdef Q_OS_LINUX
        // Linux implementation using sysinfo
        struct sysinfo info;
        if(sysinfo(&info) == 0) {
            totalMemoryBytes = info.totalram;
        }
#elif defined(Q_OS_MAC) || defined(Q_OS_DARWIN)
        // macOS implementation using sysctl
        int mib[2] = { CTL_HW, HW_MEMSIZE };
        size_t length = sizeof(totalMemoryBytes);
        if (sysctl(mib, 2, &totalMemoryBytes, &length, NULL, 0) != 0) {
            // Fallback: use a reasonable default for modern systems
            totalMemoryBytes = 8ULL * 1024 * 1024 * 1024; // Assume 8GB
        }
#elif defined(Q_OS_WIN)
        // Windows implementation using Windows API
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(memInfo);
        if (GlobalMemoryStatusEx(&memInfo)) {
            totalMemoryBytes = memInfo.ullTotalPhys;
        } else {
            // Fallback: use a reasonable default for modern systems
            totalMemoryBytes = 8ULL * 1024 * 1024 * 1024; // Assume 8GB
        }
#else
        // Fallback for other platforms: use a reasonable default
        totalMemoryBytes = 8ULL * 1024 * 1024 * 1024; // Assume 8GB
#endif

        // If we have more than 8GB RAM, use 2GB for Argon2
        if(totalMemoryBytes > (8ULL * 1024 * 1024 * 1024)) {
            memoryKb = 1 << 21; // 2 GB
        }

        // Adjust iterations if too small - higher for government security
        uint32_t time_cost = iterations > 0 ? iterations : 5;
        // Enforce minimum of 5 iterations
        time_cost = std::max(time_cost, 5U);

        // Parallelism factor - increased for multi-core systems
        uint32_t parallelism = 4; // Use 4 threads by default for modern CPUs

        // Argon2id is the preferred variant for general use cases
        int success = argon2id_hash_raw(
                         time_cost,
                         memoryKb,
                         parallelism,
                         password.data(),
                         password.size(),
                         reinterpret_cast<const unsigned char *>(salt.data()),
                         salt.size(),
                         reinterpret_cast<unsigned char *>(key.data()),
                         key.size()) == ARGON2_OK;

        if (!success)
        {
            // Fall back to Argon2i if Argon2id fails
            SECURE_LOG(WARNING, "Argon2Provider", "Argon2id failed, trying Argon2i...");
            // For fallback to Argon2i
            int success = argon2i_hash_raw(
                             time_cost,
                             memoryKb,
                             parallelism,
                             password.data(),
                             password.size(),
                             reinterpret_cast<const unsigned char *>(salt.data()),
                             salt.size(),
                             reinterpret_cast<unsigned char *>(key.data()),
                             key.size()) == ARGON2_OK;
        }
    }
    else
    {
        SECURE_LOG(WARNING, "Argon2Provider", "Only Argon2 KDF is supported");
        key.fill(0); // Clear sensitive data
        return QByteArray();
    }

    if (!success)
    {
        SECURE_LOG(ERROR, "Argon2Provider", 
            QString("Key derivation failed for KDF: %1").arg(kdf));
        // Use secure memory zeroing to prevent key material leakage
        sodium_memzero(key.data(), key.size());
        return QByteArray();
    }
    
    // Create a secure copy with proper memory protections
    QByteArray secureKey(key.size(), 0);
    
    // Lock the memory pages to prevent swapping to disk
    if (sodium_mlock(secureKey.data(), secureKey.size()) != 0) {
        SECURE_LOG(WARNING, "Argon2Provider", "Failed to lock memory pages - key material may be swapped to disk");
    }
    
    // Copy the key material to the secured memory
    memcpy(secureKey.data(), key.data(), key.size());
    
    // Erase the original key data securely
    sodium_memzero(key.data(), key.size());
    
    return secureKey;
}

bool Argon2Provider::encrypt(QFile &inputFile, QFile &outputFile, const QByteArray &key,
                             const QByteArray &iv, const QString &algorithm, bool useAuthentication)
{
    // Delegate encryption to OpenSSL since Argon2 is only a KDF
    SECURE_LOG(DEBUG, "Argon2Provider", "Delegating encryption operation to OpenSSL provider");
    return m_opensslProvider.encrypt(inputFile, outputFile, key, iv, algorithm, useAuthentication);
}

bool Argon2Provider::decrypt(QFile &inputFile, QFile &outputFile, const QByteArray &key,
                             const QByteArray &iv, const QString &algorithm, bool useAuthentication)
{
    // Delegate decryption to OpenSSL since Argon2 is only a KDF
    SECURE_LOG(DEBUG, "Argon2Provider", "Delegating decryption operation to OpenSSL provider");
    return m_opensslProvider.decrypt(inputFile, outputFile, key, iv, algorithm, useAuthentication);
}

QByteArray Argon2Provider::generateRandomBytes(int size)
{
    // Delegate to OpenSSL for random number generation
    return m_opensslProvider.generateRandomBytes(size);
}

bool Argon2Provider::isHardwareAccelerationSupported()
{
    // Argon2 doesn't have specific hardware acceleration,
    // so return the OpenSSL hardware acceleration status
    return m_opensslProvider.isHardwareAccelerationSupported();
}

QStringList Argon2Provider::supportedCiphers()
{
    // Delegate to OpenSSL for cipher support
    return m_opensslProvider.supportedCiphers();
}

QStringList Argon2Provider::supportedKDFs()
{
    // Argon2 provider primarily supports Argon2 only
    return {"Argon2"};
}