// include/chacha20.h
#ifndef CHACHA20_H
#define CHACHA20_H

#include <QByteArray>
#include <sodium.h>

class ChaCha20 {
public:
    ChaCha20();
    ~ChaCha20();
    
    // Setup methods
    bool setKey(const QByteArray& key);
    bool setNonce(const QByteArray& nonce);
    void setCounter(uint32_t counter);
    
    // Process data (encrypt or decrypt)
    QByteArray process(const QByteArray& data);
    
private:
    QByteArray key;
    QByteArray nonce;
    uint32_t counter;
};

#endif // CHACHA20_H