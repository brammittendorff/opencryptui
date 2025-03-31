#include "encryptionengine.h"
#include <QDebug>
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
        qDebug() << "No crypto providers available!";
    }
}

EncryptionEngine::~EncryptionEngine() {
    // Providers will be cleaned up automatically via unique_ptr
}

void EncryptionEngine::initializeProviders() {
    // Clear existing providers
    m_providers.clear();

    // Add providers
    try {
        m_providers.push_back(std::make_unique<OpenSSLProvider>());
        qDebug() << "OpenSSL provider initialized";
    } catch (const std::exception& e) {
        qDebug() << "Failed to initialize OpenSSL provider:" << e.what();
    }
    
    try {
        m_providers.push_back(std::make_unique<LibsodiumProvider>());
        qDebug() << "libsodium provider initialized";
    } catch (const std::exception& e) {
        qDebug() << "Failed to initialize libsodium provider:" << e.what();
    }
    
    try {
        m_providers.push_back(std::make_unique<Argon2Provider>());
        qDebug() << "Argon2 provider initialized";
    } catch (const std::exception& e) {
        qDebug() << "Failed to initialize Argon2 provider:" << e.what();
    }
}

void EncryptionEngine::setProvider(const QString& providerName) {
    CryptoProvider* foundProvider = findProvider(providerName);
    
    if (foundProvider) {
        m_currentProvider = foundProvider;
        m_currentProviderName = providerName;
        qDebug() << "Switched to" << providerName << "crypto provider";
    } else {
        qDebug() << "Provider" << providerName << "not available";
    }
}

QString EncryptionEngine::currentProvider() const {
    // If no providers, return an empty string
    if (m_providers.empty()) {
        return QString();
    }
    
    // Default to first provider's name if no current provider
    if (!m_currentProvider) {
        return m_providers[0]->providerName();
    }
    
    return m_currentProviderName;
}

QStringList EncryptionEngine::availableProviders() const {
    QStringList providers;
    for (const auto& provider : m_providers) {
        providers.append(provider->providerName());
    }
    return providers;
}

CryptoProvider* EncryptionEngine::findProvider(const QString& providerName) {
    for (const auto& provider : m_providers) {
        if (provider->providerName() == providerName) {
            return provider.get();
        }
    }
    return nullptr;
}

bool EncryptionEngine::isHardwareAccelerationSupported() const {
    if (!m_currentProvider) {
        return false;
    }
    
    return m_currentProvider->isHardwareAccelerationSupported();
}

QStringList EncryptionEngine::supportedCiphers() const {
    if (!m_currentProvider) {
        return QStringList();
    }
    
    return m_currentProvider->supportedCiphers();
}

QStringList EncryptionEngine::supportedKDFs() const {
    if (!m_currentProvider) {
        return QStringList();
    }
    
    return m_currentProvider->supportedKDFs();
}

bool EncryptionEngine::checkHardwareSupport() {
#ifdef __x86_64__
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx & bit_AES) != 0;
    }
#endif
    return false;
}