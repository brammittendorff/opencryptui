#include "encryptionengine.h"
#include "logging/secure_logger.h"
#include <sodium.h>
#include <openssl/evp.h>

#ifdef __x86_64__
#include <cpuid.h>
#endif

EncryptionEngine::EncryptionEngine() : m_currentProvider(nullptr) {
    // Initialize available crypto providers
    initializeProviders();
    
    // Set default provider (prefer OpenSSL if available)
    if (!m_providers.empty()) {
        setProvider(currentProvider());
    } else {
        SECURE_LOG(ERROR, "EncryptionEngine", "No crypto providers available!");
    }
}

EncryptionEngine::~EncryptionEngine() {
    // Providers will be cleaned up automatically via unique_ptr
    SECURE_LOG(DEBUG, "EncryptionEngine", "Encryption Engine Destructor called");
}

void EncryptionEngine::initializeProviders() {
    // Clear existing providers
    m_providers.clear();

    // Add providers
    try {
        m_providers.push_back(std::make_unique<OpenSSLProvider>());
        SECURE_LOG(INFO, "EncryptionEngine", "OpenSSL provider initialized");
    } catch (const std::exception& e) {
        SECURE_LOG(ERROR, "EncryptionEngine", 
            QString("Failed to initialize OpenSSL provider: %1").arg(e.what()));
    }
    
    try {
        m_providers.push_back(std::make_unique<LibsodiumProvider>());
        SECURE_LOG(INFO, "EncryptionEngine", "libsodium provider initialized");
    } catch (const std::exception& e) {
        SECURE_LOG(ERROR, "EncryptionEngine", 
            QString("Failed to initialize libsodium provider: %1").arg(e.what()));
    }
    
    try {
        m_providers.push_back(std::make_unique<Argon2Provider>());
        SECURE_LOG(INFO, "EncryptionEngine", "Argon2 provider initialized");
    } catch (const std::exception& e) {
        SECURE_LOG(ERROR, "EncryptionEngine", 
            QString("Failed to initialize Argon2 provider: %1").arg(e.what()));
    }
}

void EncryptionEngine::setProvider(const QString& providerName) {
    CryptoProvider* foundProvider = findProvider(providerName);
    
    if (foundProvider) {
        m_currentProvider = foundProvider;
        m_currentProviderName = providerName;
        SECURE_LOG(INFO, "EncryptionEngine", 
            QString("Switched to %1 crypto provider").arg(providerName));
    } else {
        SECURE_LOG(WARNING, "EncryptionEngine", 
            QString("Provider %1 not available").arg(providerName));
    }
}

QString EncryptionEngine::currentProvider() const {
    // If no providers, return an empty string
    if (m_providers.empty()) {
        SECURE_LOG(WARNING, "EncryptionEngine", "No providers available");
        return QString();
    }
    
    // Default to first provider's name if no current provider
    if (!m_currentProvider) {
        QString defaultProvider = m_providers[0]->providerName();
        SECURE_LOG(DEBUG, "EncryptionEngine", 
            QString("Defaulting to first provider: %1").arg(defaultProvider));
        return defaultProvider;
    }
    
    return m_currentProviderName;
}

QStringList EncryptionEngine::availableProviders() const {
    QStringList providers;
    for (const auto& provider : m_providers) {
        providers.append(provider->providerName());
    }
    
    SECURE_LOG(DEBUG, "EncryptionEngine", 
        QString("Available providers: %1").arg(providers.join(", ")));
    
    return providers;
}

CryptoProvider* EncryptionEngine::findProvider(const QString& providerName) {
    for (const auto& provider : m_providers) {
        if (provider->providerName() == providerName) {
            SECURE_LOG(DEBUG, "EncryptionEngine", 
                QString("Provider found: %1").arg(providerName));
            return provider.get();
        }
    }
    
    SECURE_LOG(WARNING, "EncryptionEngine", 
        QString("Provider not found: %1").arg(providerName));
    return nullptr;
}

bool EncryptionEngine::isHardwareAccelerationSupported() const {
    if (!m_currentProvider) {
        SECURE_LOG(WARNING, "EncryptionEngine", "No current provider set");
        return false;
    }
    
    bool supported = m_currentProvider->isHardwareAccelerationSupported();
    SECURE_LOG(DEBUG, "EncryptionEngine", 
        QString("Hardware Acceleration Supported: %1")
        .arg(supported ? "Yes" : "No"));
    
    return supported;
}

QStringList EncryptionEngine::supportedCiphers() const {
    if (!m_currentProvider) {
        SECURE_LOG(WARNING, "EncryptionEngine", "No current provider set");
        return QStringList();
    }
    
    QStringList ciphers = m_currentProvider->supportedCiphers();
    SECURE_LOG(DEBUG, "EncryptionEngine", 
        QString("Supported Ciphers: %1").arg(ciphers.join(", ")));
    
    return ciphers;
}

QStringList EncryptionEngine::supportedKDFs() const {
    if (!m_currentProvider) {
        SECURE_LOG(WARNING, "EncryptionEngine", "No current provider set");
        return QStringList();
    }
    
    QStringList kdfs = m_currentProvider->supportedKDFs();
    SECURE_LOG(DEBUG, "EncryptionEngine", 
        QString("Supported KDFs: %1").arg(kdfs.join(", ")));
    
    return kdfs;
}

bool EncryptionEngine::checkHardwareSupport() {
#ifdef __x86_64__
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        bool hasAES = (ecx & bit_AES) != 0;
        SECURE_LOG(DEBUG, "EncryptionEngine", 
            QString("AES Hardware Support Detected: %1")
            .arg(hasAES ? "Yes" : "No"));
        return hasAES;
    }
#endif
    SECURE_LOG(DEBUG, "EncryptionEngine", "No hardware support detection available");
    return false;
}
