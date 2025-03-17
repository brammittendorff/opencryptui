// src/encryptionengine_chacha20.cpp
#include "encryptionengine.h"
#include "chacha20.h"
#include <QFile>
#include <QDebug>
#include <sodium.h>
#include <openssl/crypto.h>

bool EncryptionEngine::encryptWithCustomChaCha20(const QString& inputPath, const QString& outputPath, 
                                               const QString& password, const QByteArray& salt,
                                               const QStringList& keyfilePaths) {
    QFile inputFile(inputPath);
    QFile outputFile(outputPath);
    
    if (!inputFile.open(QIODevice::ReadOnly)) {
        qDebug() << "Failed to open input file:" << inputPath;
        return false;
    }

    if (!outputFile.open(QIODevice::WriteOnly)) {
        qDebug() << "Failed to open output file:" << outputPath;
        inputFile.close();
        return false;
    }
    
    // Generate salt if not provided
    QByteArray actualSalt;
    if (salt.isEmpty()) {
        actualSalt.resize(crypto_pwhash_SALTBYTES);
        randombytes_buf(actualSalt.data(), actualSalt.size());
    } else {
        actualSalt = salt;
    }
    
    // Generate nonce
    QByteArray nonce(crypto_stream_chacha20_ietf_NONCEBYTES, 0);
    randombytes_buf(nonce.data(), nonce.size());
    
    // Derive key using our enhanced key derivation
    QByteArray key = deriveKey(password, actualSalt, keyfilePaths, "Argon2", 10);
    if (key.isEmpty()) {
        qDebug() << "Key derivation failed";
        inputFile.close();
        outputFile.close();
        return false;
    }
    
    // Ensure key is the right size for ChaCha20
    if (key.size() > crypto_stream_chacha20_ietf_KEYBYTES) {
        key.resize(crypto_stream_chacha20_ietf_KEYBYTES);
    }
    
    // Initialize our custom ChaCha20 implementation
    ChaCha20 chacha;
    if (!chacha.setKey(key)) {
        qDebug() << "Failed to set ChaCha20 key";
        OPENSSL_cleanse(key.data(), key.size());
        inputFile.close();
        outputFile.close();
        return false;
    }
    
    if (!chacha.setNonce(nonce)) {
        qDebug() << "Failed to set ChaCha20 nonce";
        OPENSSL_cleanse(key.data(), key.size());
        inputFile.close();
        outputFile.close();
        return false;
    }
    
    // Write salt and nonce to the output file
    outputFile.write(actualSalt);
    outputFile.write(nonce);
    
    // Process data in chunks
    const int chunkSize = 4096;
    QByteArray chunk;
    
    while (!inputFile.atEnd()) {
        chunk = inputFile.read(chunkSize);
        QByteArray encrypted = chacha.process(chunk);
        outputFile.write(encrypted);
    }
    
    // Clean up
    OPENSSL_cleanse(key.data(), key.size());
    inputFile.close();
    outputFile.close();
    
    return true;
}

bool EncryptionEngine::decryptWithCustomChaCha20(const QString& inputPath, const QString& outputPath,
                                               const QString& password, const QStringList& keyfilePaths) {
    QFile inputFile(inputPath);
    QFile outputFile(outputPath);
    
    if (!inputFile.open(QIODevice::ReadOnly)) {
        qDebug() << "Failed to open input file:" << inputPath;
        return false;
    }

    if (!outputFile.open(QIODevice::WriteOnly)) {
        qDebug() << "Failed to open output file:" << outputPath;
        inputFile.close();
        return false;
    }
    
    // Read salt and nonce
    QByteArray salt(crypto_pwhash_SALTBYTES, 0);
    QByteArray nonce(crypto_stream_chacha20_ietf_NONCEBYTES, 0);
    
    if (inputFile.read(salt.data(), salt.size()) != salt.size()) {
        qDebug() << "Failed to read salt from file";
        inputFile.close();
        outputFile.close();
        return false;
    }
    
    if (inputFile.read(nonce.data(), nonce.size()) != nonce.size()) {
        qDebug() << "Failed to read nonce from file";
        inputFile.close();
        outputFile.close();
        return false;
    }
    
    // Derive key using our enhanced key derivation
    QByteArray key = deriveKey(password, salt, keyfilePaths, "Argon2", 10);
    if (key.isEmpty()) {
        qDebug() << "Key derivation failed";
        inputFile.close();
        outputFile.close();
        return false;
    }
    
    // Ensure key is the right size for ChaCha20
    if (key.size() > crypto_stream_chacha20_ietf_KEYBYTES) {
        key.resize(crypto_stream_chacha20_ietf_KEYBYTES);
    }
    
    // Initialize our custom ChaCha20 implementation
    ChaCha20 chacha;
    if (!chacha.setKey(key)) {
        qDebug() << "Failed to set ChaCha20 key";
        OPENSSL_cleanse(key.data(), key.size());
        inputFile.close();
        outputFile.close();
        return false;
    }
    
    if (!chacha.setNonce(nonce)) {
        qDebug() << "Failed to set ChaCha20 nonce";
        OPENSSL_cleanse(key.data(), key.size());
        inputFile.close();
        outputFile.close();
        return false;
    }
    
    // Process data in chunks
    const int chunkSize = 4096;
    QByteArray chunk;
    
    while (!inputFile.atEnd()) {
        chunk = inputFile.read(chunkSize);
        QByteArray decrypted = chacha.process(chunk);
        outputFile.write(decrypted);
    }
    
    // Clean up
    OPENSSL_cleanse(key.data(), key.size());
    inputFile.close();
    outputFile.close();
    
    return true;
}
