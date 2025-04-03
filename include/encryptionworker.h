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
    void setDiskParameters(const QString &diskPath, const QString &password, const QString &algorithm,
                         const QString &kdf, int iterations, bool useHMAC, bool encrypt, const QStringList &keyfilePaths);
    void setDiskParametersWithHiddenVolume(const QString &diskPath, const QString &outerPassword, const QString &hiddenPassword, 
                                         qint64 hiddenVolumeSize, const QString &algorithm, const QString &kdf, 
                                         int iterations, bool useHMAC, const QStringList &keyfilePaths);

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
    bool isDisk;
    bool isHiddenVolume;
    QString hiddenPassword;
    qint64 hiddenVolumeSize;
    QString customHeader;
    QStringList keyfilePaths;
    EncryptionEngine engine;

    QStringList benchmarkAlgorithms;
    QStringList benchmarkKdfs;

    qint64 getFileSizeInBytes(const QString &path);
    void benchmarkCipher(const QString &algorithm, const QString &kdf, bool useHardwareAcceleration);
};

#endif // ENCRYPTIONWORKER_H
