#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QBuffer>
#include <QDebug>
#include <QThread>
#include <QTextStream>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QKeyEvent>
#include <QInputDialog>
#include <QCoreApplication>
#include <QDirIterator>
#include <QJsonDocument>
#include <QJsonObject>
#include <QFile>
#include <QDir>
#include "encryptionengine.h"
#include <QDirIterator>
#include <QProcess>
#include "version.h"
#include "encryptionworker.h"

// Add the static member initialization here
QTextStream* MainWindow::s_logStream = nullptr;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , worker(new EncryptionWorker)
    , m_signalsConnected(false)  // Initialize the flag
{
    qDebug() << "MainWindow Constructor";
    ui->setupUi(this);
    setupUI();

    // Load theme preference
    loadPreferences();

    // Set default values for iterations
    ui->iterationsSpinBox->setValue(10);
    ui->folderIterationsSpinBox->setValue(10);

    // Ensure connectSignalsAndSlots is called only once
    static bool connectionsSet = false;
    if (!connectionsSet) {
        connectSignalsAndSlots();
        connectionsSet = true;
    }

    checkHardwareAcceleration();

    worker->moveToThread(&workerThread);
    connect(&workerThread, &QThread::finished, worker, &QObject::deleteLater);
    connect(worker, &EncryptionWorker::progress, this, &MainWindow::updateProgress);
    connect(worker, &EncryptionWorker::finished, this, &MainWindow::handleFinished);
    connect(worker, &EncryptionWorker::estimatedTime, this, &MainWindow::showEstimatedTime);
    connect(worker, &EncryptionWorker::benchmarkResultReady, this, &MainWindow::updateBenchmarkTable);

    workerThread.start();

    // Initialize the benchmark table
    ui->benchmarkTable->setColumnCount(5);
    QStringList headers = {"Iterations", "MB/s", "ms", "Cipher", "KDF"};
    ui->benchmarkTable->setHorizontalHeaderLabels(headers);
    ui->benchmarkTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    // Enable sorting
    ui->benchmarkTable->setSortingEnabled(true);
}

MainWindow::~MainWindow()
{
        // Save preferences before closing
    savePreferences();

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

    // Install event filter on all relevant widgets
    ui->filePasswordLineEdit->installEventFilter(this);
    ui->folderPasswordLineEdit->installEventFilter(this);
    ui->fileEncryptButton->installEventFilter(this);
    ui->fileDecryptButton->installEventFilter(this);
    ui->folderEncryptButton->installEventFilter(this);
    ui->folderDecryptButton->installEventFilter(this);
}

void MainWindow::setupComboBoxes() {
    QStringList algorithms = {
        "AES-256-GCM", "ChaCha20-Poly1305", "AES-256-CTR", "AES-256-CBC",
        "AES-128-GCM", "AES-128-CTR", "AES-192-GCM", "AES-192-CTR",
        "AES-128-CBC", "AES-192-CBC", "Camellia-256-CBC", "Camellia-128-CBC"
    };
    ui->fileAlgorithmComboBox->addItems(algorithms);
    ui->folderAlgorithmComboBox->addItems(algorithms);

    QStringList kdfs = {"PBKDF2", "Argon2", "Scrypt"};
    ui->kdfComboBox->addItems(kdfs);
    ui->folderKdfComboBox->addItems(kdfs);

    ui->iterationsSpinBox->setValue(10);
    ui->folderIterationsSpinBox->setValue(10);

    ui->hmacCheckBox->setChecked(true);
    ui->folderHmacCheckBox->setChecked(true);
}

void MainWindow::connectSignalsAndSlots()
{
    if (m_signalsConnected) {
        qDebug() << "Signals already connected, skipping...";
        return;
    }

    qDebug() << "Connecting signals and slots";

    // File encryption/decryption
    safeConnect(ui->fileEncryptButton, SIGNAL(clicked()), this, SLOT(on_fileEncryptButton_clicked()));
    safeConnect(ui->fileDecryptButton, SIGNAL(clicked()), this, SLOT(on_fileDecryptButton_clicked()));

    // Folder encryption/decryption
    safeConnect(ui->folderEncryptButton, SIGNAL(clicked()), this, SLOT(on_folderEncryptButton_clicked()));
    safeConnect(ui->folderDecryptButton, SIGNAL(clicked()), this, SLOT(on_folderDecryptButton_clicked()));

    // Other button connections
    safeConnect(ui->fileBrowseButton, SIGNAL(clicked()), this, SLOT(on_fileBrowseButton_clicked()));
    safeConnect(ui->fileKeyfileBrowseButton, SIGNAL(clicked()), this, SLOT(on_fileKeyfileBrowseButton_clicked()));
    safeConnect(ui->folderBrowseButton, SIGNAL(clicked()), this, SLOT(on_folderBrowseButton_clicked()));
    safeConnect(ui->folderKeyfileBrowseButton, SIGNAL(clicked()), this, SLOT(on_folderKeyfileBrowseButton_clicked()));
    safeConnect(ui->benchmarkButton, SIGNAL(clicked()), this, SLOT(on_benchmarkButton_clicked()));

    // Menu actions
    safeConnect(ui->actionExit, SIGNAL(triggered()), this, SLOT(on_actionExit_triggered()));
    safeConnect(ui->actionPreferences, SIGNAL(triggered()), this, SLOT(on_actionPreferences_triggered()));
    safeConnect(ui->actionAbout, SIGNAL(triggered()), this, SLOT(on_actionAbout_triggered()));

    m_signalsConnected = true;
}

void MainWindow::on_fileEncryptButton_clicked()
{
    qDebug() << "File Encrypt Button Clicked or Enter pressed";
    startWorker(true, true);
}

void MainWindow::on_fileDecryptButton_clicked()
{
    qDebug() << "File Decrypt Button Clicked or Enter pressed";
    startWorker(false, true);
}

void MainWindow::on_folderEncryptButton_clicked()
{
    qDebug() << "Folder Encrypt Button Clicked or Enter pressed";
    startWorker(true, false);
}

void MainWindow::on_folderDecryptButton_clicked()
{
    qDebug() << "Folder Decrypt Button Clicked or Enter pressed";
    startWorker(false, false);
}

void MainWindow::startWorker(bool encrypt, bool isFile)
{
    qDebug() << "Start Worker: encrypt=" << encrypt << ", isFile=" << isFile;
    QString path = isFile ? ui->filePathLineEdit->text() : ui->folderPathLineEdit->text();
    QString password = isFile ? ui->filePasswordLineEdit->text() : ui->folderPasswordLineEdit->text();
    QString algorithm = isFile ? ui->fileAlgorithmComboBox->currentText() : ui->folderAlgorithmComboBox->currentText();
    QString kdf = isFile ? ui->kdfComboBox->currentText() : ui->folderKdfComboBox->currentText();
    int iterations = isFile ? ui->iterationsSpinBox->value() : ui->folderIterationsSpinBox->value();
    bool useHMAC = isFile ? ui->hmacCheckBox->isChecked() : ui->folderHmacCheckBox->isChecked();
    QStringList keyfilePaths = isFile ? ui->fileKeyfileListWidget->getAllItems() : ui->folderKeyfileListWidget->getAllItems(); // Using the new method
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

    worker->setParameters(path, password, algorithm, kdf, iterations, useHMAC, encrypt, isFile, customHeader, keyfilePaths);
    QMetaObject::invokeMethod(worker, "process", Qt::QueuedConnection);
}

void MainWindow::updateProgress(int value)
{
    qDebug() << "Update Progress: value=" << value;
    ui->fileProgressBar->setValue(value);
    ui->folderProgressBar->setValue(value);
}

void MainWindow::handleFinished(bool success, const QString &errorMessage)
{
    qDebug() << "Handle Finished: success=" << success << ", errorMessage=" << errorMessage;
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
    qDebug() << "Show Estimated Time: seconds=" << seconds;
    QString timeText = QString("Estimated time: %1 seconds").arg(seconds, 0, 'f', 2);
    ui->fileEstimatedTimeLabel->setText(timeText);
    ui->folderEstimatedTimeLabel->setText(timeText);
}

void MainWindow::on_fileBrowseButton_clicked()
{
    static int callCount = 0;
    qDebug() << "File Browse Button Clicked (Call #" << ++callCount << ")";
    QString filePath = QFileDialog::getOpenFileName(this, "Select File");
    if (!filePath.isEmpty()) {
        ui->filePathLineEdit->setText(filePath);
    }
}

void MainWindow::on_folderBrowseButton_clicked()
{
    qDebug() << "Folder Browse Button Clicked";
    QString folderPath = QFileDialog::getExistingDirectory(this, "Select Folder");
    if (!folderPath.isEmpty()) {
        ui->folderPathLineEdit->setText(folderPath);
    }
}

void MainWindow::on_fileKeyfileBrowseButton_clicked()
{
    qDebug() << "File Keyfile Browse Button Clicked";
    QStringList keyfilePaths = QFileDialog::getOpenFileNames(this, "Select Keyfiles");
    if (!keyfilePaths.isEmpty()) {
        for (const QString &path : keyfilePaths) {
            ui->fileKeyfileListWidget->addItem(path);
        }
    }
}

void MainWindow::on_folderKeyfileBrowseButton_clicked()
{
    qDebug() << "Folder Keyfile Browse Button Clicked";
    QStringList keyfilePaths = QFileDialog::getOpenFileNames(this, "Select Keyfiles");
    if (!keyfilePaths.isEmpty()) {
        for (const QString &path : keyfilePaths) {
            ui->folderKeyfileListWidget->addItem(path);
        }
    }
}

void MainWindow::checkHardwareAcceleration() {
    bool supported = encryptionEngine.isHardwareAccelerationSupported();
    QString status = supported ? "Supported" : "Not supported";
    qDebug() << "Hardware Acceleration: " + status;
}

void MainWindow::on_benchmarkButton_clicked()
{
    ui->benchmarkTable->setRowCount(0); // Clear previous results
    qDebug() << "Running benchmark...";

    QStringList algorithms = {
        "AES-256-GCM", "ChaCha20-Poly1305", "AES-256-CTR", "AES-256-CBC",
        "AES-128-GCM", "AES-128-CTR", "AES-192-GCM", "AES-192-CTR",
        "AES-128-CBC", "AES-192-CBC", "Camellia-256-CBC", "Camellia-128-CBC"
    };

    QStringList kdfs = {"PBKDF2", "Argon2", "Scrypt"};

    worker->setBenchmarkParameters(algorithms, kdfs);
    QMetaObject::invokeMethod(worker, "runBenchmark", Qt::QueuedConnection);
}

void MainWindow::messageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg)
{
    if (s_logStream)
    {
        *s_logStream << msg << Qt::endl;
        QTextStream(stdout) << msg << Qt::endl;
    }
}

void MainWindow::updateBenchmarkTable(int iterations, double mbps, double ms, const QString &cipher, const QString &kdf) {
    qDebug() << "Update Benchmark Table: iterations=" << iterations << ", mbps=" << mbps << ", ms=" << ms << ", cipher=" << cipher << ", kdf=" << kdf;
    int row = ui->benchmarkTable->rowCount();
    ui->benchmarkTable->insertRow(row);

    ui->benchmarkTable->setItem(row, 0, new QTableWidgetItem(QString::number(iterations)));
    ui->benchmarkTable->setItem(row, 1, new QTableWidgetItem(QString::number(mbps, 'f', 2)));
    ui->benchmarkTable->setItem(row, 2, new QTableWidgetItem(QString::number(ms, 'f', 2)));
    ui->benchmarkTable->setItem(row, 3, new QTableWidgetItem(cipher));
    ui->benchmarkTable->setItem(row, 4, new QTableWidgetItem(kdf));
}

void MainWindow::safeConnect(const QObject* sender, const char* signal, const QObject* receiver, const char* method)
{
    disconnect(sender, signal, receiver, method);  // First disconnect any existing connection
    connect(sender, signal, receiver, method, Qt::UniqueConnection);  // Then connect with UniqueConnection
}

bool MainWindow::eventFilter(QObject *obj, QEvent *event)
{
    if (event->type() == QEvent::KeyPress) {
        QKeyEvent *keyEvent = static_cast<QKeyEvent *>(event);
        if (keyEvent->key() == Qt::Key_Return || keyEvent->key() == Qt::Key_Enter) {
            if (obj == ui->filePasswordLineEdit || obj == ui->fileEncryptButton) {
                qDebug() << "Enter pressed for file encryption";
                ui->fileEncryptButton->click();
                return true;
            } else if (obj == ui->fileDecryptButton) {
                qDebug() << "Enter pressed for file decryption";
                ui->fileDecryptButton->click();
                return true;
            } else if (obj == ui->folderPasswordLineEdit || obj == ui->folderEncryptButton) {
                qDebug() << "Enter pressed for folder encryption";
                ui->folderEncryptButton->click();
                return true;
            } else if (obj == ui->folderDecryptButton) {
                qDebug() << "Enter pressed for folder decryption";
                ui->folderDecryptButton->click();
                return true;
            }
        }
    }
    return QObject::eventFilter(obj, event);
}

void MainWindow::on_actionExit_triggered()
{
    QApplication::quit();
}

void MainWindow::on_actionPreferences_triggered()
{
    QStringList themes = {"Light", "Dark"};
    bool ok;
    QString theme = QInputDialog::getItem(this, "Select Theme", "Theme:", themes, 0, false, &ok);
    if (ok && !theme.isEmpty()) {
        applyTheme(theme);
    }
}

void MainWindow::on_actionAbout_triggered()
{
    QString aboutText = QString(
        "Open Encryption UI\n"
        "Version: %1\n"
        "Latest Commit: %2\n"
        "Hardware Acceleration: %3"
    ).arg(GIT_TAG)
     .arg(GIT_COMMIT_HASH)
     .arg(encryptionEngine.isHardwareAccelerationSupported() ? "Supported" : "Not supported");

    QMessageBox::about(this, "About", aboutText);
}

void MainWindow::applyTheme(const QString &theme) {
    QString themeFilePath;
    if (theme == "Dark") {
        themeFilePath = ":/resources/darktheme.qss";
    } else {
        themeFilePath = ":/resources/lighttheme.qss";
    }

    qDebug() << "Trying to load stylesheet from:" << themeFilePath;

    QFile file(themeFilePath);

    if (!file.exists()) {
        qDebug() << "QSS file does not exist at path:" << themeFilePath;
        return;
    }

    if (file.open(QFile::ReadOnly)) {
        QString styleSheet = QLatin1String(file.readAll());
        qApp->setStyleSheet(styleSheet);
        file.close();
        currentTheme = theme;  // Update current theme
        qDebug() << "Successfully applied theme from:" << themeFilePath;
    } else {
        qDebug() << "Failed to open theme file:" << file.errorString();
    }
}

void MainWindow::loadPreferences()
{
    QString settingsDirPath = QDir::homePath() + "/.opencryptui";
    QString settingsFilePath = settingsDirPath + "/config.json";

    QDir settingsDir(settingsDirPath);
    if (!settingsDir.exists()) {
        if (!settingsDir.mkpath(settingsDirPath)) {
            qDebug() << "Failed to create settings directory:" << settingsDirPath;
            applyTheme("Light");
            return;
        }
    }

    QFile settingsFile(settingsFilePath);

    if (!settingsFile.exists()) {
        qDebug() << "Settings file not found, applying default theme.";
        applyTheme("Light");
        return;
    }

    if (!settingsFile.open(QIODevice::ReadOnly)) {
        qDebug() << "Failed to open settings file for reading:" << settingsFile.errorString();
        applyTheme("Light");
        return;
    }

    QByteArray settingsData = settingsFile.readAll();
    QJsonDocument settingsDoc = QJsonDocument::fromJson(settingsData);
    QJsonObject settingsObj = settingsDoc.object();

    QString theme = settingsObj.value("theme").toString("Light");
    applyTheme(theme);

    settingsFile.close();
}

void MainWindow::savePreferences()
{
    QString settingsDirPath = QDir::homePath() + "/.opencryptui";
    QString settingsFilePath = settingsDirPath + "/config.json";

    QDir settingsDir(settingsDirPath);
    if (!settingsDir.exists()) {
        if (!settingsDir.mkpath(settingsDirPath)) {
            qDebug() << "Failed to create settings directory:" << settingsDirPath;
            return;
        }
    }

    QFile settingsFile(settingsFilePath);

    if (!settingsFile.open(QIODevice::WriteOnly)) {
        qDebug() << "Failed to open settings file for writing:" << settingsFile.errorString();
        return;
    }

    QJsonObject settingsObj;
    settingsObj["theme"] = currentTheme; // Assuming currentTheme is a member variable holding the current theme

    QJsonDocument settingsDoc(settingsObj);
    settingsFile.write(settingsDoc.toJson());

    settingsFile.close();
}
