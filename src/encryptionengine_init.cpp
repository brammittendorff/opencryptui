#include "encryptionengine.h"
#include <QDebug>
#include <sodium.h>
#include <openssl/evp.h>
#include <cpuid.h>


EncryptionEngine::EncryptionEngine() {
    OpenSSL_add_all_algorithms();
    if (sodium_init() < 0) {
        qDebug() << "Failed to initialize libsodium";
        throw std::runtime_error("Failed to initialize libsodium");
    }
    m_aesNiSupported = checkHardwareSupport();
    if (m_aesNiSupported) {
        qDebug() << "AES-NI hardware acceleration is supported";
    } else {
        qDebug() << "AES-NI hardware acceleration is not supported";
    }
}

EncryptionEngine::~EncryptionEngine() {
    EVP_cleanup();
}

bool EncryptionEngine::isHardwareAccelerationSupported() const {
    return m_aesNiSupported;
}

QByteArray EncryptionEngine::getLastIv() const {
    return lastIv;
}

bool EncryptionEngine::checkHardwareSupport() {
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx & bit_AES) != 0;
    }
    return false;
}

const EVP_CIPHER* EncryptionEngine::getHardwareAcceleratedCipher(const QString& algorithm) {
    if (m_aesNiSupported) {
        if (algorithm == "AES-256-CBC") return EVP_aes_256_cbc();
        if (algorithm == "AES-256-GCM") return EVP_aes_256_gcm();
        if (algorithm == "AES-256-CTR") return EVP_aes_256_ctr();
        if (algorithm == "AES-128-CBC") return EVP_aes_128_cbc();
        if (algorithm == "AES-128-GCM") return EVP_aes_128_gcm();
        if (algorithm == "AES-128-CTR") return EVP_aes_128_ctr();
        if (algorithm == "AES-192-CBC") return EVP_aes_192_cbc();
        if (algorithm == "AES-192-GCM") return EVP_aes_192_gcm();
        if (algorithm == "AES-192-CTR") return EVP_aes_192_ctr();
    }
    return nullptr;
}
