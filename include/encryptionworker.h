#ifndef ENCRYPTIONWORKER_H
#define ENCRYPTIONWORKER_H

#include <QObject>
#include <QByteArray>
#include <QString>
#include <QStringList>
#include "encryptionengine.h"

class EncryptionWorker : public QObject
{
    Q_OBJECT

public:
    explicit EncryptionWorker(QObject *parent = nullptr);
    ~EncryptionWorker();

    void setParameters(const QString &path, const QString &password,
                       const QString &algorithm, const QString &kdf,
                       int iterations, bool useHMAC, bool encrypt, bool isFile,
                       const QString &customHeader, const QStringList &keyfilePaths);
    void setBenchmarkParameters(const QStringList &algorithms, const QStringList &kdfs);
    void setDiskParameters(const QString &diskPath, const QString &password, const QString &algorithm,
                         const QString &kdf, int iterations, bool useHMAC, bool encrypt, const QStringList &keyfilePaths);
    void setDiskParametersWithHiddenVolume(const QString &diskPath, const QString &outerPassword, const QString &hiddenPassword, 
                                         qint64 hiddenVolumeSize, const QString &algorithm, const QString &kdf, 
                                         int iterations, bool useHMAC, const QStringList &keyfilePaths);

public slots:
    void process();
    void processDiskOperation();
    void processBenchmark();
    void runBenchmark();

signals:
    void progress(int percent);
    void finished(const QString &result, bool success, bool isFile);
    void estimatedTime(const QString &timeStr);
    void benchmarkResultReady(int iterations, double mbps, double ms, 
                             const QString &algorithm, const QString &kdf);

private:
    QString m_path;
    QString m_password;
    QString m_algorithm;
    QString m_kdf;
    int m_iterations;
    bool m_useHMAC;
    bool m_encrypt;
    bool m_isFile;
    bool isDisk;
    bool m_isHiddenVolume;
    QString m_hiddenPassword;
    qint64 m_hiddenVolumeSize;
    QString m_customHeader;
    QStringList m_keyfilePaths;
    EncryptionEngine m_engine;

    QStringList m_benchmarkAlgorithms;
    QStringList m_benchmarkKDFs;
    QList<int> m_benchmarkIterations;
    qint64 m_benchmarkFileSizeInMB;

    void benchmarkCipher(const QString &algorithm, const QString &kdf, bool useHardwareAcceleration);
    qint64 getFileSizeInBytes(const QString &path);
};

#endif // ENCRYPTIONWORKER_H 