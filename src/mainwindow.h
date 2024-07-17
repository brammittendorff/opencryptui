#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
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

private:
    Ui::MainWindow *ui;
    EncryptionEngine encryptionEngine;
    QStandardItemModel *drivesModel;
    QThread workerThread;
    EncryptionWorker *worker;

    void setupUI();
    void setupComboBoxes();
    void connectSignalsAndSlots();
    void startWorker(bool encrypt, bool isFile);
};

#endif // MAINWINDOW_H
