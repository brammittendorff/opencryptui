#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QBuffer>
#include <QTextStream>
#include <QStandardItemModel>
#include <QComboBox>
#include <QPushButton>
#include "encryptionengine.h"
#include "encryptionworker.h"
#include <QThread>
#include "customlistwidget.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QFile>
#include <QDir>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    EncryptionEngine encryptionEngine;
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    bool eventFilter(QObject *obj, QEvent *event) override;

private slots:
    void on_fileEncryptButton_clicked();
    void on_fileDecryptButton_clicked();
    void on_fileBrowseButton_clicked();
    void on_fileKeyfileBrowseButton_clicked();
    void on_folderEncryptButton_clicked();
    void on_folderDecryptButton_clicked();
    void on_folderBrowseButton_clicked();
    void on_folderKeyfileBrowseButton_clicked();
    void updateProgress(int value);
    void handleFinished(bool success, const QString &errorMessage);
    void showEstimatedTime(double seconds);
    void on_benchmarkButton_clicked();

    // New slots for menu actions
    void on_actionExit_triggered();
    void on_actionPreferences_triggered();
    void on_actionAbout_triggered();
    void on_actionAboutCiphers_triggered();
    void on_actionAboutKDFs_triggered();
    void on_actionAboutIterations_triggered();  // Add this line
    void applyTheme(const QString &theme);
    void on_cryptoProviderComboBox_currentIndexChanged(const QString &providerName);
    void showProviderCapabilities();

private:
    Ui::MainWindow *ui;
    QStandardItemModel *drivesModel;
    QThread workerThread;
    EncryptionWorker *worker;
    static QTextStream* s_logStream;
    bool m_signalsConnected;
    QString currentTheme;

    void setupUI();
    void setupComboBoxes();
    void connectSignalsAndSlots();
    void startWorker(bool encrypt, bool isFile);

    // Add these member variables
    QComboBox* m_cryptoProviderComboBox;
    QPushButton* m_providerInfoButton;

    void checkHardwareAcceleration();

    static void messageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg);
    void updateBenchmarkTable(int iterations, double mbps, double ms, const QString &cipher, const QString &kdf);

    void safeConnect(const QObject* sender, const char* signal, const QObject* receiver, const char* method);

    void loadPreferences();
    void savePreferences();
};

#endif // MAINWINDOW_H
