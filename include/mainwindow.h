#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QBuffer>
#include <QTextStream>
#include <QStandardItemModel>
#include "encryptionengine.h"
#include "encryptionworker.h"
#include <QThread>
#include "customlistwidget.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_fileEncryptButton_clicked();
    void on_fileDecryptButton_clicked();
    void on_fileBrowseButton_clicked();
    void on_fileKeyfileBrowseButton_clicked(); // New slot
    void on_folderEncryptButton_clicked();
    void on_folderDecryptButton_clicked();
    void on_folderBrowseButton_clicked();
    void on_folderKeyfileBrowseButton_clicked(); // New slot
    void updateProgress(int value);
    void handleFinished(bool success, const QString &errorMessage);
    void showEstimatedTime(double seconds);
    void on_benchmarkButton_clicked();

private:
    Ui::MainWindow *ui;
    EncryptionEngine encryptionEngine;
    QStandardItemModel *drivesModel;
    QThread workerThread;
    EncryptionWorker *worker;
    static QTextStream* s_logStream;
    bool m_signalsConnected;  // Add this line

    void setupUI();
    void setupComboBoxes();
    void connectSignalsAndSlots();
    void startWorker(bool encrypt, bool isFile);

    void checkHardwareAcceleration();

    static void messageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg);
    void updateBenchmarkTable(int iterations, double mbps, double ms, const QString &cipher, const QString &kdf);

    void safeConnect(const QObject* sender, const char* signal, const QObject* receiver, const char* method);
};

#endif // MAINWINDOW_H
