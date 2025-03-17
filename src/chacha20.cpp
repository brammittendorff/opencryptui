// src/chacha20.cpp
#include "chacha20.h"
#include <QDebug>

ChaCha20::ChaCha20() : counter(0) {
    // Initialize empty key and nonce
}

ChaCha20::~ChaCha20() {
    // Clear sensitive data
    if (!key.isEmpty()) {
        sodium_memzero(key.data(), key.size());
    }
    if (!nonce.isEmpty()) {
        sodium_memzero(nonce.data(), nonce.size());
    }
}

bool ChaCha20::setKey(const QByteArray& newKey) {
    if (newKey.size() != crypto_stream_chacha20_ietf_KEYBYTES) {
        qDebug() << "ChaCha20 requires a" << crypto_stream_chacha20_ietf_KEYBYTES << "byte key";
        return false;
    }
    
    // Store the key
    key = newKey;
    return true;
}

bool ChaCha20::setNonce(const QByteArray& newNonce) {
    if (newNonce.size() != crypto_stream_chacha20_ietf_NONCEBYTES) {
        qDebug() << "ChaCha20 requires a" << crypto_stream_chacha20_ietf_NONCEBYTES << "byte nonce";
        return false;
    }
    
    // Store the nonce
    nonce = newNonce;
    return true;
}

void ChaCha20::setCounter(uint32_t newCounter) {
    counter = newCounter;
}

QByteArray ChaCha20::process(const QByteArray& data) {
    if (key.isEmpty() || nonce.isEmpty()) {
        qDebug() << "ChaCha20: Key or nonce not set properly";
        return QByteArray();
    }
    
    QByteArray result(data.size(), 0);
    
    // Encrypt/decrypt the data
    if (crypto_stream_chacha20_ietf_xor_ic(
            reinterpret_cast<unsigned char*>(result.data()),
            reinterpret_cast<const unsigned char*>(data.constData()),
            data.size(),
            reinterpret_cast<const unsigned char*>(nonce.constData()),
            counter,
            reinterpret_cast<const unsigned char*>(key.constData())) != 0) {
        qDebug() << "ChaCha20 encryption/decryption failed";
        return QByteArray();
    }
    
    return result;
}