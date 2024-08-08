#ifndef ENCRYPTIONWORKER_H
#define ENCRYPTIONWORKER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include "encryptionengine.h"

class EncryptionWorker : public QObject
{
    Q_OBJECT
public:
    explicit EncryptionWorker(QObject *parent = nullptr);
    void setParameters(const QString &path, const QString &password, const QString &algorithm,
                       const QString &kdf, int iterations, bool useHMAC, bool encrypt, bool isFile, const QString &customHeader, const QStringList &keyfilePaths);
    void setBenchmarkParameters(const QStringList &algorithms, const QStringList &kdfs);

public slots:
    void process();
    void runBenchmark();

signals:
    void progress(int value);
    void finished(bool success, const QString &errorMessage);
    void estimatedTime(double seconds);
    void benchmarkResultReady(int iterations, double mbps, double ms, const QString &cipher, const QString &kdf);

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
    QStringList keyfilePaths;
    EncryptionEngine engine;

    QStringList benchmarkAlgorithms;
    QStringList benchmarkKdfs;

    qint64 getFileSizeInBytes(const QString &path);
    void benchmarkCipher(const QString &algorithm, const QString &kdf, bool useHardwareAcceleration);
};

#endif // ENCRYPTIONWORKER_H
