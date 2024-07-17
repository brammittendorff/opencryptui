#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QDebug>
#include <QThread>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , worker(new EncryptionWorker)
{
    qDebug() << "MainWindow Constructor";
    ui->setupUi(this);
    setupUI();

    // Set default values for iterations
    ui->iterationsSpinBox->setValue(10);
    ui->folderIterationsSpinBox->setValue(10);

    connectSignalsAndSlots();

    worker->moveToThread(&workerThread);
    connect(&workerThread, &QThread::finished, worker, &QObject::deleteLater);
    connect(worker, &EncryptionWorker::progress, this, &MainWindow::updateProgress);
    connect(worker, &EncryptionWorker::finished, this, &MainWindow::handleFinished);
    connect(worker, &EncryptionWorker::estimatedTime, this, &MainWindow::showEstimatedTime);
    workerThread.start();
}

MainWindow::~MainWindow()
{
    workerThread.quit();
    workerThread.wait();
    qDebug() << "MainWindow Destructor";
    delete ui;
}

void MainWindow::setupUI()
{
    setupComboBoxes();
    ui->fileProgressBar->setVisible(false);
    ui->fileEstimatedTimeLabel->setVisible(false);
    ui->folderProgressBar->setVisible(false);
    ui->folderEstimatedTimeLabel->setVisible(false);
}

void MainWindow::setupComboBoxes() {
    QStringList algorithms = {
        "AES-256-CBC", "AES-256-GCM", "AES-256-CTR", 
        "ChaCha20-Poly1305", "Twofish-256-CBC", 
        "Serpent-256-CBC", "Blowfish-256-CBC", 
        "Camellia-256-CBC", "Camellia-256-GCM", "AES-128-CBC"
    };
    ui->fileAlgorithmComboBox->addItems(algorithms);
    ui->folderAlgorithmComboBox->addItems(algorithms);

    QStringList kdfs = {"PBKDF2", "Argon2", "Scrypt"};
    ui->kdfComboBox->addItems(kdfs);
    ui->folderKdfComboBox->addItems(kdfs);

    ui->iterationsSpinBox->setValue(100000);
    ui->folderIterationsSpinBox->setValue(100000);

    ui->hmacCheckBox->setChecked(true);
    ui->folderHmacCheckBox->setChecked(true);
}

void MainWindow::connectSignalsAndSlots()
{
    connect(ui->fileEncryptButton, &QPushButton::clicked, this, &MainWindow::on_fileEncryptButton_clicked);
    connect(ui->fileDecryptButton, &QPushButton::clicked, this, &MainWindow::on_fileDecryptButton_clicked);
    connect(ui->fileBrowseButton, &QPushButton::clicked, this, &MainWindow::on_fileBrowseButton_clicked);
    connect(ui->folderEncryptButton, &QPushButton::clicked, this, &MainWindow::on_folderEncryptButton_clicked);
    connect(ui->folderDecryptButton, &QPushButton::clicked, this, &MainWindow::on_folderDecryptButton_clicked);
    connect(ui->folderBrowseButton, &QPushButton::clicked, this, &MainWindow::on_folderBrowseButton_clicked);
}

void MainWindow::on_fileEncryptButton_clicked()
{
    startWorker(true, true);
}

void MainWindow::on_fileDecryptButton_clicked()
{
    startWorker(false, true);
}

void MainWindow::on_folderEncryptButton_clicked()
{
    startWorker(true, false);
}

void MainWindow::on_folderDecryptButton_clicked()
{
    startWorker(false, false);
}

void MainWindow::startWorker(bool encrypt, bool isFile)
{
    QString path = isFile ? ui->filePathLineEdit->text() : ui->folderPathLineEdit->text();
    QString password = isFile ? ui->filePasswordLineEdit->text() : ui->folderPasswordLineEdit->text();
    QString algorithm = isFile ? ui->fileAlgorithmComboBox->currentText() : ui->folderAlgorithmComboBox->currentText();
    QString kdf = isFile ? ui->kdfComboBox->currentText() : ui->folderKdfComboBox->currentText();
    int iterations = isFile ? ui->iterationsSpinBox->value() : ui->folderIterationsSpinBox->value();
    bool useHMAC = isFile ? ui->hmacCheckBox->isChecked() : ui->folderHmacCheckBox->isChecked();
    QString customHeader = ""; // or any specific header if needed

    if (path.isEmpty() || password.isEmpty()) {
        QMessageBox::warning(this, "Error", "Please provide path and password.");
        return;
    }

    QProgressBar* progressBar = isFile ? ui->fileProgressBar : ui->folderProgressBar;
    QLabel* estimatedTimeLabel = isFile ? ui->fileEstimatedTimeLabel : ui->folderEstimatedTimeLabel;

    progressBar->setVisible(true);
    progressBar->setValue(0);
    estimatedTimeLabel->setVisible(true);
    estimatedTimeLabel->setText("Estimated time: calculating...");

    worker->setParameters(path, password, algorithm, kdf, iterations, useHMAC, encrypt, isFile, customHeader);
    QMetaObject::invokeMethod(worker, "process", Qt::QueuedConnection);
}

void MainWindow::updateProgress(int value)
{
    ui->fileProgressBar->setValue(value);
    ui->folderProgressBar->setValue(value);
}

void MainWindow::handleFinished(bool success, const QString &errorMessage)
{
    ui->fileProgressBar->setVisible(false);
    ui->folderProgressBar->setVisible(false);
    ui->fileEstimatedTimeLabel->setVisible(false);
    ui->folderEstimatedTimeLabel->setVisible(false);
    if (success) {
        QMessageBox::information(this, "Success", "Operation completed successfully.");
    } else {
        QMessageBox::critical(this, "Error", errorMessage);
    }
}

void MainWindow::showEstimatedTime(double seconds)
{
    QString timeText = QString("Estimated time: %1 seconds").arg(seconds, 0, 'f', 2);
    ui->fileEstimatedTimeLabel->setText(timeText);
    ui->folderEstimatedTimeLabel->setText(timeText);
}

void MainWindow::on_fileBrowseButton_clicked()
{
    QString filePath = QFileDialog::getOpenFileName(this, "Select File");
    if (!filePath.isEmpty()) {
        ui->filePathLineEdit->setText(filePath);
    }
}

void MainWindow::on_folderBrowseButton_clicked()
{
    QString folderPath = QFileDialog::getExistingDirectory(this, "Select Folder");
    if (!folderPath.isEmpty()) {
        ui->folderPathLineEdit->setText(folderPath);
    }
}
