#ifndef ENCRYPTIONWORKER_H
#define ENCRYPTIONWORKER_H

#include <QObject>
#include <QString>
#include "encryptionengine.h"

class EncryptionWorker : public QObject
{
    Q_OBJECT
public:
    explicit EncryptionWorker(QObject *parent = nullptr);
    void setParameters(const QString &path, const QString &password, const QString &algorithm,
                       const QString &kdf, int iterations, bool useHMAC, bool encrypt, bool isFile, const QString &customHeader);

public slots:
    void process();

signals:
    void progress(int value);
    void finished(bool success, const QString &errorMessage);
    void estimatedTime(double seconds);

private:
    QString path;
    QString password;
    QString algorithm;
    QString kdf;
    int iterations;
    bool useHMAC;
    bool encrypt;
    bool isFile;
    QString customHeader;
    EncryptionEngine engine;

    void encryptFile();
    void decryptFile();
    void encryptFolder();
    void decryptFolder();
};

#endif // ENCRYPTIONWORKER_H
