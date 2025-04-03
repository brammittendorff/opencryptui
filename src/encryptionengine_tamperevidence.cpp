#include "encryptionengine.h"
#include "logging/secure_logger.h"
#include <QFile>
#include <QDataStream>
#include <sodium.h>
#include <openssl/evp.h>
#include <algorithm> // For std::min

// Generate a digital signature for tamper evidence
QByteArray EncryptionEngine::generateDigitalSignature(QFile& inputFile, const QByteArray& key)
{
    // Save current file position
    qint64 originalPosition = inputFile.pos();
    
    // Reset to beginning of file
    inputFile.seek(0);
    
    // Create a key for Ed25519 signature (32 bytes)
    QByteArray signatureKey(crypto_sign_SECRETKEYBYTES, 0);
    
    // Derive a separate key for signing
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
    
    // Include original key and a fixed suffix for domain separation
    QByteArray signingMaterial = key;
    signingMaterial.append("SIG_KEY_DOMAIN_SEPARATION");
    
    EVP_DigestUpdate(mdctx, signingMaterial.constData(), signingMaterial.size());
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;
    EVP_DigestFinal_ex(mdctx, hash, &hashLen);
    EVP_MD_CTX_free(mdctx);
    
    // Use the hash as seed for signature key
    memcpy(signatureKey.data(), hash, std::min<size_t>(hashLen, crypto_sign_SECRETKEYBYTES));
    
    // Generate corresponding public key
    QByteArray publicKey(crypto_sign_PUBLICKEYBYTES, 0);
    crypto_sign_seed_keypair(reinterpret_cast<unsigned char*>(publicKey.data()), 
                           reinterpret_cast<unsigned char*>(signatureKey.data()),
                           reinterpret_cast<const unsigned char*>(signatureKey.constData()));
    
    // Hash the file content in chunks
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
    
    QByteArray buffer(4096, 0);
    while (!inputFile.atEnd()) {
        qint64 bytesRead = inputFile.read(buffer.data(), buffer.size());
        EVP_DigestUpdate(mdctx, buffer.constData(), bytesRead);
    }
    
    EVP_DigestFinal_ex(mdctx, hash, &hashLen);
    EVP_MD_CTX_free(mdctx);
    
    // Create signature
    QByteArray signature(crypto_sign_BYTES + hashLen, 0);
    unsigned long long signatureLen;
    
    crypto_sign_detached(reinterpret_cast<unsigned char*>(signature.data()),
                        &signatureLen,
                        hash,
                        hashLen,
                        reinterpret_cast<const unsigned char*>(signatureKey.constData()));
    
    // Resize to actual signature length
    signature.resize(signatureLen);
    
    // Append public key to signature for verification
    signature.append(publicKey);
    
    // Securely erase temporary keys
    sodium_memzero(signatureKey.data(), signatureKey.size());
    
    // Reset file position
    inputFile.seek(originalPosition);
    
    SECURE_LOG(DEBUG, "EncryptionEngine", "Generated digital signature for tamper evidence");
    return signature;
}

// Append signature to encrypted file
void EncryptionEngine::appendSignature(QFile& outputFile, const QByteArray& signature)
{
    // Go to end of file
    outputFile.seek(outputFile.size());
    
    // Write signature length and signature
    QDataStream out(&outputFile);
    out.setByteOrder(QDataStream::BigEndian);
    
    // Write a magic number for signature identification
    out << quint32(0x5349475F); // "SIG_"
    
    // Write signature length
    out << quint32(signature.size());
    
    // Write the signature itself
    outputFile.write(signature);
    
    // Write a CRC32 checksum for the signature block
    quint32 crc = calculateCRC32(signature);
    out << crc;
    
    SECURE_LOG(DEBUG, "EncryptionEngine", QString("Appended digital signature (%1 bytes) to encrypted file").arg(signature.size()));
}

// Verify signature from encrypted file
bool EncryptionEngine::verifySignature(QFile& inputFile, const QByteArray& key, QByteArray& storedSignature)
{
    // Save original position
    qint64 originalPosition = inputFile.pos();
    
    // Go near the end of file to check for signature block
    if (inputFile.size() < 16) {
        // Too small to have a signature
        inputFile.seek(originalPosition);
        return false;
    }
    
    // Look for signature block at the end
    // Check if there's enough room for a signature block
    if (inputFile.size() < 64) { // Reasonable minimum size for a signed file
        inputFile.seek(originalPosition);
        return false;
    }
    
    inputFile.seek(inputFile.size() - 12); // Magic + length + CRC
    
    QDataStream in(&inputFile);
    in.setByteOrder(QDataStream::BigEndian);
    
    // Read magic number
    quint32 magic;
    in >> magic;
    
    if (magic != 0x5349475F) {
        // No signature block found
        inputFile.seek(originalPosition);
        return false;
    }
    
    // Read signature length
    quint32 signatureLength;
    in >> signatureLength;
    
    // Sanity check
    if (signatureLength > 10 * 1024 || // Max 10KB for signature (very generous)
        signatureLength > inputFile.size() - 12) {
        
        SECURE_LOG(WARNING, "EncryptionEngine", "Invalid signature length detected");
        inputFile.seek(originalPosition);
        return false;
    }
    
    // Go to signature start
    inputFile.seek(inputFile.size() - 12 - signatureLength);
    
    // Read signature
    storedSignature = inputFile.read(signatureLength);
    
    // Read CRC
    inputFile.seek(inputFile.size() - 4);
    quint32 storedCrc;
    in >> storedCrc;
    
    // Verify CRC
    quint32 calculatedCrc = calculateCRC32(storedSignature);
    if (calculatedCrc != storedCrc) {
        SECURE_LOG(WARNING, "EncryptionEngine", "Signature CRC check failed");
        inputFile.seek(originalPosition);
        return false;
    }
    
    // Split signature and public key
    if (storedSignature.size() < crypto_sign_BYTES + crypto_sign_PUBLICKEYBYTES) {
        SECURE_LOG(WARNING, "EncryptionEngine", "Signature too short");
        inputFile.seek(originalPosition);
        return false;
    }
    
    QByteArray actualSignature = storedSignature.left(crypto_sign_BYTES);
    QByteArray publicKey = storedSignature.right(crypto_sign_PUBLICKEYBYTES);
    
    // Verify public key is derived from our key
    QByteArray expectedPublicKey(crypto_sign_PUBLICKEYBYTES, 0);
    QByteArray derivedPrivateKey(crypto_sign_SECRETKEYBYTES, 0);
    
    // Derive private key same way as during signing
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
    
    QByteArray signingMaterial = key;
    signingMaterial.append("SIG_KEY_DOMAIN_SEPARATION");
    
    EVP_DigestUpdate(mdctx, signingMaterial.constData(), signingMaterial.size());
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;
    EVP_DigestFinal_ex(mdctx, hash, &hashLen);
    EVP_MD_CTX_free(mdctx);
    
    // Copy derived key
    memcpy(derivedPrivateKey.data(), hash, std::min<size_t>(hashLen, crypto_sign_SECRETKEYBYTES));
    
    // Generate expected public key
    crypto_sign_seed_keypair(reinterpret_cast<unsigned char*>(expectedPublicKey.data()),
                            reinterpret_cast<unsigned char*>(derivedPrivateKey.data()),
                            reinterpret_cast<const unsigned char*>(derivedPrivateKey.constData()));
    
    // Securely clear sensitive data
    sodium_memzero(derivedPrivateKey.data(), derivedPrivateKey.size());
    
    // Compare public keys
    if (publicKey != expectedPublicKey) {
        SECURE_LOG(WARNING, "EncryptionEngine", "Signature verification failed: invalid public key");
        inputFile.seek(originalPosition);
        return false;
    }
    
    // Hash the file content (excluding signature block)
    inputFile.seek(0);
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
    
    qint64 dataSize = inputFile.size() - 12 - signatureLength;
    QByteArray buffer(4096, 0);
    
    qint64 remaining = dataSize;
    while (remaining > 0) {
        qint64 toRead = std::min(remaining, static_cast<qint64>(buffer.size()));
        qint64 bytesRead = inputFile.read(buffer.data(), toRead);
        
        if (bytesRead <= 0) break;
        
        EVP_DigestUpdate(mdctx, buffer.constData(), bytesRead);
        remaining -= bytesRead;
    }
    
    EVP_DigestFinal_ex(mdctx, hash, &hashLen);
    EVP_MD_CTX_free(mdctx);
    
    // Verify signature
    int result = crypto_sign_verify_detached(
        reinterpret_cast<const unsigned char*>(actualSignature.constData()),
        hash,
        hashLen,
        reinterpret_cast<const unsigned char*>(publicKey.constData()));
    
    // Reset file position
    inputFile.seek(originalPosition);
    
    if (result != 0) {
        SECURE_LOG(WARNING, "EncryptionEngine", "Signature verification failed: invalid signature");
        return false;
    }
    
    SECURE_LOG(DEBUG, "EncryptionEngine", "Digital signature verified successfully");
    return true;
}

// Calculate CRC32 checksum for integrity checks
quint32 EncryptionEngine::calculateCRC32(const QByteArray& data)
{
    quint32 crc = 0xFFFFFFFF;
    static const quint32 crcTable[256] = {
        0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535,
        0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD,
        0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D,
        0x6DDDE4EB, 0xF4D4B551, 0x83D385C7, 0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
        0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4,
        0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
        0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59, 0x26D930AC,
        0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
        0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB,
        0xB6662D3D, 0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F,
        0x9FBFE4A5, 0xE8B8D433, 0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB,
        0x086D3D2D, 0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
        0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA,
        0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65, 0x4DB26158, 0x3AB551CE,
        0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A,
        0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
        0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409,
        0xCE61E49F, 0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
        0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739,
        0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
        0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1, 0xF00F9344, 0x8708A3D2, 0x1E01F268,
        0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0,
        0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8,
        0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
        0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF,
        0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703,
        0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7,
        0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D, 0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
        0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE,
        0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
        0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777, 0x88085AE6,
        0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
        0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D,
        0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5,
        0x47B2CF7F, 0x30B5FFE9, 0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605,
        0xCDD70693, 0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
        0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
    };
    
    for (int i = 0; i < data.size(); i++) {
        crc = (crc >> 8) ^ crcTable[(crc ^ static_cast<unsigned char>(data[i])) & 0xFF];
    }
    
    return ~crc;
}