#include "encryptionengine.h"
#include <QDebug>
#include <sodium.h>
#include <openssl/evp.h>

#ifdef __x86_64__
#include <cpuid.h>
#endif

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
#ifdef __x86_64__
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx & bit_AES) != 0;
    }
#endif
    return false;
}
