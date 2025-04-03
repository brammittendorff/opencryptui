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
#include <QTimer>
#include <QProgressBar>
#include <QLabel>
#include <QCheckBox>
#include "encryptionengine.h"
#include <QDirIterator>
#include <QProcess>
#include "version.h"
#include "encryptionworker.h"
#include <QStatusBar>
#include <QStandardPaths>

// Add the static member initialization here
QTextStream *MainWindow::s_logStream = nullptr;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow), worker(new EncryptionWorker), m_signalsConnected(false) // Initialize the flag
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
    if (!connectionsSet)
    {
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

void MainWindow::setupUI()
{
    setupComboBoxes();
    ui->fileProgressBar->setVisible(false);
    ui->fileEstimatedTimeLabel->setVisible(false);
    ui->folderProgressBar->setVisible(false);
    ui->folderEstimatedTimeLabel->setVisible(false);
    ui->diskProgressBar->setVisible(false);
    ui->diskEstimatedTimeLabel->setVisible(false);
    
    // Create and set up security status labels
    fileSecurityStatusLabel = new QLabel(this);
    folderSecurityStatusLabel = new QLabel(this);
    diskSecurityStatusLabel = new QLabel(this);
    
    // Style the labels
    QString baseStyle = "font-weight: bold; padding: 5px; border-radius: 3px;";
    fileSecurityStatusLabel->setStyleSheet(baseStyle);
    folderSecurityStatusLabel->setStyleSheet(baseStyle);
    diskSecurityStatusLabel->setStyleSheet(baseStyle);
    
    // Add labels to layout near path fields
    ui->fileSelectionLayout->addWidget(fileSecurityStatusLabel);
    ui->folderSelectionLayout->addWidget(folderSecurityStatusLabel);
    ui->diskSelectionLayout->addWidget(diskSecurityStatusLabel);

    // Add crypto provider items
    QStringList providers = encryptionEngine.availableProviders();
    ui->m_cryptoProviderComboBox->addItems(providers);
    if (!providers.isEmpty())
    {
        ui->m_cryptoProviderComboBox->setCurrentText(encryptionEngine.currentProvider());
    }

    // Update the connection for crypto provider selection
    connect(ui->m_cryptoProviderComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            [this](int index)
            {
                QString providerName = ui->m_cryptoProviderComboBox->itemText(index);
                on_cryptoProviderComboBox_currentIndexChanged(providerName);
            });

    connect(ui->m_providerInfoButton, &QPushButton::clicked, this, &MainWindow::showProviderCapabilities);

    // Install event filter on all relevant widgets
    ui->filePasswordLineEdit->installEventFilter(this);
    ui->folderPasswordLineEdit->installEventFilter(this);
    ui->diskPasswordLineEdit->installEventFilter(this);
    ui->fileEncryptButton->installEventFilter(this);
    ui->fileDecryptButton->installEventFilter(this);
    ui->folderEncryptButton->installEventFilter(this);
    ui->folderDecryptButton->installEventFilter(this);
    ui->diskEncryptButton->installEventFilter(this);
    ui->diskDecryptButton->installEventFilter(this);
    
    // Initialize disk encryption tab
    ui->diskIterationsSpinBox->setValue(10);
    ui->diskHmacCheckBox->setChecked(true);
    
    // Populate disk selection dropdown
    on_refreshDisksButton_clicked();
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

void MainWindow::setupComboBoxes()
{
    QStringList algorithms = {// Add this slot implementation:
                              "AES-256-GCM", "ChaCha20-Poly1305", "AES-256-CTR", "AES-256-CBC",
                              "AES-128-GCM", "AES-128-CTR", "AES-192-GCM", "AES-192-CTR",
                              "AES-128-CBC", "AES-192-CBC", "Camellia-256-CBC", "Camellia-128-CBC"};
    ui->fileAlgorithmComboBox->addItems(algorithms);
    ui->folderAlgorithmComboBox->addItems(algorithms);
    ui->diskAlgorithmComboBox->addItems(algorithms);

    QStringList kdfs = {"Scrypt", "PBKDF2"};

    ui->kdfComboBox->addItems(kdfs);
    ui->folderKdfComboBox->addItems(kdfs);
    ui->diskKdfComboBox->addItems(kdfs);

    ui->iterationsSpinBox->setValue(10);
    ui->folderIterationsSpinBox->setValue(10);
    ui->diskIterationsSpinBox->setValue(10);

    ui->hmacCheckBox->setChecked(true);
    ui->folderHmacCheckBox->setChecked(true);
    ui->diskHmacCheckBox->setChecked(true);
}

void MainWindow::updateSecurityStatus(const QString &path, QLabel *statusLabel)
{
    if (!statusLabel || path.isEmpty()) return;
    
    QFileInfo fileInfo(path);
    bool isSecure = true;
    QString statusText;
    QString styleSheet = "font-weight: bold; padding: 5px; border-radius: 3px;";
    
    // Check if in standard temp directory
    if (path.startsWith("/tmp/") || path.startsWith(QDir::tempPath())) {
        isSecure = false;
        statusText = "⚠️ INSECURE: File in temporary directory";
    }
    
    // Check if in user's home directory with proper permissions
    else if (fileInfo.exists()) {
        QFile file(path);
        QFileDevice::Permissions perms = file.permissions();
        
        // Check if world-readable
        if (perms & QFileDevice::ReadOther) {
            isSecure = false;
            statusText = "⚠️ INSECURE: File readable by others";
        }
        
        // Check if world-writable
        else if (perms & QFileDevice::WriteOther) {
            isSecure = false;
            statusText = "⚠️ INSECURE: File writable by others";
        }
        
        // Check if in a world-readable directory
        else {
            QString parentDir = fileInfo.absolutePath();
            QFileInfo dirInfo(parentDir);
            if (QFile(parentDir).permissions() & QFileDevice::ReadOther) {
                isSecure = false;
                statusText = "⚠️ WARNING: Parent directory accessible by others";
            }
        }
    }
    
    // Default secure status
    if (isSecure) {
        statusText = "✅ SECURE: Location has proper permissions";
        styleSheet += "background-color: #d4edda; color: #155724;";
    } else {
        styleSheet += "background-color: #f8d7da; color: #721c24;";
    }
    
    statusLabel->setText(statusText);
    statusLabel->setStyleSheet(styleSheet);
    statusLabel->setVisible(true);
}

void MainWindow::showSecurityTips(const QString &context)
{
    QString tips;
    
    if (context == "file") {
        tips = "File Encryption Security Tips:\n\n"
               "• Store encrypted files in private locations only you can access\n"
               "• Use both a strong password AND keyfile for critical files\n"
               "• Enable HMAC for file integrity verification\n"
               "• For maximum security, use AES-256-GCM or ChaCha20-Poly1305\n"
               "• Verify file permissions before and after encryption\n"
               "• Create encrypted backups stored in separate locations";
    }
    else if (context == "folder") {
        tips = "Folder Encryption Security Tips:\n\n"
               "• Choose a secure location for your encrypted folder\n"
               "• Use a different password than for individual files\n"
               "• Consider encrypted containers instead of folder encryption\n"
               "• Keep an inventory of encrypted folder contents\n"
               "• Test decryption regularly to ensure accessibility";
    }
    else if (context == "disk") {
        tips = "Disk Encryption Security Tips:\n\n"
               "• Always use full disk encryption for portable devices\n"
               "• Create a secure rescue key and store it separately\n"
               "• Remember that disk encryption doesn't protect mounted volumes\n"
               "• Consider hidden volumes for plausible deniability\n"
               "• Keep firmware and encryption software updated\n"
               "• Combine with strong boot password for maximum security";
    }
    else {
        tips = "General Encryption Security Tips:\n\n"
               "• Use unique strong passwords (16+ characters)\n"
               "• Store keyfiles on separate physical devices\n"
               "• Never share encryption passwords electronically\n"
               "• Choose secure storage locations with proper permissions\n"
               "• Regular backup your encrypted data and keys\n"
               "• Be aware of physical security (shoulder surfing)";
    }
    
    QMessageBox tipBox;
    tipBox.setWindowTitle("Security Tips");
    tipBox.setText(tips);
    tipBox.setIcon(QMessageBox::Information);
    
    // Add button to view comprehensive security guide
    tipBox.addButton("Close", QMessageBox::RejectRole);
    QPushButton *guideButton = tipBox.addButton("Full Security Guide", QMessageBox::ActionRole);
    
    tipBox.exec();
    
    if (tipBox.clickedButton() == guideButton) {
        on_actionSecurityGuide_triggered();
    }
}

void MainWindow::connectSignalsAndSlots()
{
    if (m_signalsConnected)
    {
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

    // Disk encryption/decryption
    safeConnect(ui->diskEncryptButton, SIGNAL(clicked()), this, SLOT(on_diskEncryptButton_clicked()));
    safeConnect(ui->diskDecryptButton, SIGNAL(clicked()), this, SLOT(on_diskDecryptButton_clicked()));
    safeConnect(ui->diskBrowseButton, SIGNAL(clicked()), this, SLOT(on_diskBrowseButton_clicked()));
    safeConnect(ui->diskKeyfileBrowseButton, SIGNAL(clicked()), this, SLOT(on_diskKeyfileBrowseButton_clicked()));
    safeConnect(ui->refreshDisksButton, SIGNAL(clicked()), this, SLOT(on_refreshDisksButton_clicked()));

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
    safeConnect(ui->actionAboutCiphers, SIGNAL(triggered()), this, SLOT(on_actionAboutCiphers_triggered()));
    safeConnect(ui->actionAboutKDFs, SIGNAL(triggered()), this, SLOT(on_actionAboutKDFs_triggered()));
    safeConnect(ui->actionAboutIterations, SIGNAL(triggered()), this, SLOT(on_actionAboutIterations_triggered()));
    safeConnect(ui->actionSecurityGuide, SIGNAL(triggered()), this, SLOT(on_actionSecurityGuide_triggered()));
    
    // Connect path changes to security status updates
    connect(ui->filePathLineEdit, &QLineEdit::textChanged, [this](const QString &text) {
        updateSecurityStatus(text, fileSecurityStatusLabel);
    });
    connect(ui->folderPathLineEdit, &QLineEdit::textChanged, [this](const QString &text) {
        updateSecurityStatus(text, folderSecurityStatusLabel);
    });
    connect(ui->diskPathLineEdit, &QLineEdit::textChanged, [this](const QString &text) {
        updateSecurityStatus(text, diskSecurityStatusLabel);
    });
    
    // Add security tip buttons
    QPushButton* fileHelpBtn = new QPushButton(QIcon::fromTheme("help-contents"), "Security Tips", this);
    QPushButton* folderHelpBtn = new QPushButton(QIcon::fromTheme("help-contents"), "Security Tips", this);
    QPushButton* diskHelpBtn = new QPushButton(QIcon::fromTheme("help-contents"), "Security Tips", this);
    
    ui->fileEncryptionGroup->layout()->addWidget(fileHelpBtn);
    ui->folderEncryptionGroup->layout()->addWidget(folderHelpBtn);
    ui->diskEncryptionGroup->layout()->addWidget(diskHelpBtn);
    
    connect(fileHelpBtn, &QPushButton::clicked, [this](){ showSecurityTips("file"); });
    connect(folderHelpBtn, &QPushButton::clicked, [this](){ showSecurityTips("folder"); });
    connect(diskHelpBtn, &QPushButton::clicked, [this](){ showSecurityTips("disk"); });

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
    QStringList keyfilePaths = isFile ? ui->fileKeyfileListWidget->getAllItems() : ui->folderKeyfileListWidget->getAllItems();
    QString customHeader = ""; // or any specific header if needed

    if (path.isEmpty() || password.isEmpty())
    {
        QMessageBox::warning(this, "Error", "Please provide path and password.");
        return;
    }

    // Validate that the selected algorithm and KDF are supported by the current provider
    QStringList supportedCiphers = encryptionEngine.supportedCiphers();
    QStringList supportedKDFs = encryptionEngine.supportedKDFs();

    if (!supportedCiphers.contains(algorithm))
    {
        QMessageBox::warning(this, "Error",
                             QString("The selected cipher '%1' is not supported by the %2 provider.\n\n"
                                     "Please select from: %3")
                                 .arg(algorithm)
                                 .arg(encryptionEngine.currentProvider())
                                 .arg(supportedCiphers.join(", ")));
        return;
    }

    if (!supportedKDFs.contains(kdf))
    {
        QMessageBox::warning(this, "Error",
                             QString("The selected KDF '%1' is not supported by the %2 provider.\n\n"
                                     "Please select from: %3")
                                 .arg(kdf)
                                 .arg(encryptionEngine.currentProvider())
                                 .arg(supportedKDFs.join(", ")));
        return;
    }

    QProgressBar *progressBar = isFile ? ui->fileProgressBar : ui->folderProgressBar;
    QLabel *estimatedTimeLabel = isFile ? ui->fileEstimatedTimeLabel : ui->folderEstimatedTimeLabel;

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
    ui->diskProgressBar->setValue(value);
}

void MainWindow::handleFinished(bool success, const QString &errorMessage)
{
    qDebug() << "Handle Finished: success=" << success << ", errorMessage=" << errorMessage;
    ui->fileProgressBar->setVisible(false);
    ui->folderProgressBar->setVisible(false);
    ui->diskProgressBar->setVisible(false);
    ui->fileEstimatedTimeLabel->setVisible(false);
    ui->folderEstimatedTimeLabel->setVisible(false);
    ui->diskEstimatedTimeLabel->setVisible(false);
    ui->fileEncryptButton->setEnabled(true);
    ui->fileDecryptButton->setEnabled(true);
    ui->folderEncryptButton->setEnabled(true);
    ui->folderDecryptButton->setEnabled(true);
    ui->diskEncryptButton->setEnabled(true);
    ui->diskDecryptButton->setEnabled(true);
    
    if (success)
    {
        QMessageBox::information(this, "Success", "Operation completed successfully.");
    }
    else
    {
        QMessageBox::critical(this, "Error", errorMessage);
    }
}

void MainWindow::showEstimatedTime(double seconds)
{
    qDebug() << "Show Estimated Time: seconds=" << seconds;
    QString timeText = QString("Estimated time: %1 seconds").arg(seconds, 0, 'f', 2);
    ui->fileEstimatedTimeLabel->setText(timeText);
    ui->folderEstimatedTimeLabel->setText(timeText);
    ui->diskEstimatedTimeLabel->setText(timeText);
}

void MainWindow::on_fileBrowseButton_clicked()
{
    static int callCount = 0;
    qDebug() << "File Browse Button Clicked (Call #" << ++callCount << ")";
    QString filePath = QFileDialog::getOpenFileName(this, "Select File");
    if (!filePath.isEmpty())
    {
        ui->filePathLineEdit->setText(filePath);
        updateSecurityStatus(filePath, fileSecurityStatusLabel);
    }
}

void MainWindow::on_folderBrowseButton_clicked()
{
    qDebug() << "Folder Browse Button Clicked";
    QString folderPath = QFileDialog::getExistingDirectory(this, "Select Folder");
    if (!folderPath.isEmpty())
    {
        ui->folderPathLineEdit->setText(folderPath);
        updateSecurityStatus(folderPath, folderSecurityStatusLabel);
    }
}

void MainWindow::on_fileKeyfileBrowseButton_clicked()
{
    qDebug() << "File Keyfile Browse Button Clicked";
    QStringList keyfilePaths = QFileDialog::getOpenFileNames(this, "Select Keyfiles");
    if (!keyfilePaths.isEmpty())
    {
        for (const QString &path : keyfilePaths)
        {
            ui->fileKeyfileListWidget->addItem(path);
        }
    }
}

void MainWindow::on_folderKeyfileBrowseButton_clicked()
{
    qDebug() << "Folder Keyfile Browse Button Clicked";
    QStringList keyfilePaths = QFileDialog::getOpenFileNames(this, "Select Keyfiles");
    if (!keyfilePaths.isEmpty())
    {
        for (const QString &path : keyfilePaths)
        {
            ui->folderKeyfileListWidget->addItem(path);
        }
    }
}

void MainWindow::checkHardwareAcceleration()
{
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
        "AES-128-CBC", "AES-192-CBC", "Camellia-256-CBC", "Camellia-128-CBC"};

    QStringList kdfs = {"Argon2", "Scrypt", "PBKDF2"};

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

void MainWindow::updateBenchmarkTable(int iterations, double mbps, double ms, const QString &cipher, const QString &kdf)
{
    qDebug() << "Update Benchmark Table: iterations=" << iterations << ", mbps=" << mbps << ", ms=" << ms << ", cipher=" << cipher << ", kdf=" << kdf;
    int row = ui->benchmarkTable->rowCount();
    ui->benchmarkTable->insertRow(row);

    ui->benchmarkTable->setItem(row, 0, new QTableWidgetItem(QString::number(iterations)));
    ui->benchmarkTable->setItem(row, 1, new QTableWidgetItem(QString::number(mbps, 'f', 2)));
    ui->benchmarkTable->setItem(row, 2, new QTableWidgetItem(QString::number(ms, 'f', 2)));
    ui->benchmarkTable->setItem(row, 3, new QTableWidgetItem(cipher));
    ui->benchmarkTable->setItem(row, 4, new QTableWidgetItem(kdf));
}

void MainWindow::safeConnect(const QObject *sender, const char *signal, const QObject *receiver, const char *method)
{
    disconnect(sender, signal, receiver, method);                    // First disconnect any existing connection
    connect(sender, signal, receiver, method, Qt::UniqueConnection); // Then connect with UniqueConnection
}

bool MainWindow::eventFilter(QObject *obj, QEvent *event)
{
    if (event->type() == QEvent::KeyPress)
    {
        QKeyEvent *keyEvent = static_cast<QKeyEvent *>(event);
        if (keyEvent->key() == Qt::Key_Return || keyEvent->key() == Qt::Key_Enter)
        {
            if (obj == ui->filePasswordLineEdit || obj == ui->fileEncryptButton)
            {
                qDebug() << "Enter pressed for file encryption";
                ui->fileEncryptButton->click();
                return true;
            }
            else if (obj == ui->fileDecryptButton)
            {
                qDebug() << "Enter pressed for file decryption";
                ui->fileDecryptButton->click();
                return true;
            }
            else if (obj == ui->folderPasswordLineEdit || obj == ui->folderEncryptButton)
            {
                qDebug() << "Enter pressed for folder encryption";
                ui->folderEncryptButton->click();
                return true;
            }
            else if (obj == ui->folderDecryptButton)
            {
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
    if (ok && !theme.isEmpty())
    {
        applyTheme(theme);
    }
}

void MainWindow::on_actionAbout_triggered()
{
    QString aboutText = QString(
                            "Open Encryption UI\n"
                            "Version: %1\n"
                            "Latest Commit: %2\n"
                            "Hardware Acceleration: %3")
                            .arg(GIT_TAG)
                            .arg(GIT_COMMIT_HASH)
                            .arg(encryptionEngine.isHardwareAccelerationSupported() ? "Supported" : "Not supported");

    QMessageBox::about(this, "About", aboutText);
}

void MainWindow::applyTheme(const QString &theme)
{
    QString themeFilePath;
    if (theme == "Dark")
    {
        themeFilePath = ":/resources/darktheme.qss";
    }
    else
    {
        themeFilePath = ":/resources/lighttheme.qss";
    }

    qDebug() << "Trying to load stylesheet from:" << themeFilePath;

    QFile file(themeFilePath);

    if (!file.exists())
    {
        qDebug() << "QSS file does not exist at path:" << themeFilePath;
        return;
    }

    if (file.open(QFile::ReadOnly))
    {
        QString styleSheet = QLatin1String(file.readAll());
        qApp->setStyleSheet(styleSheet);
        file.close();
        currentTheme = theme; // Update current theme
        qDebug() << "Successfully applied theme from:" << themeFilePath;
    }
    else
    {
        qDebug() << "Failed to open theme file:" << file.errorString();
    }
}

void MainWindow::loadPreferences()
{
    QString settingsDirPath = QDir::homePath() + "/.opencryptui";
    QString settingsFilePath = settingsDirPath + "/config.json";

    QDir settingsDir(settingsDirPath);
    if (!settingsDir.exists())
    {
        if (!settingsDir.mkpath(settingsDirPath))
        {
            qDebug() << "Failed to create settings directory:" << settingsDirPath;
            applyTheme("Light");
            return;
        }
    }

    QFile settingsFile(settingsFilePath);

    if (!settingsFile.exists())
    {
        qDebug() << "Settings file not found, applying default theme.";
        applyTheme("Light");
        return;
    }

    if (!settingsFile.open(QIODevice::ReadOnly))
    {
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
    if (!settingsDir.exists())
    {
        if (!settingsDir.mkpath(settingsDirPath))
        {
            qDebug() << "Failed to create settings directory:" << settingsDirPath;
            return;
        }
    }

    QFile settingsFile(settingsFilePath);

    if (!settingsFile.open(QIODevice::WriteOnly))
    {
        qDebug() << "Failed to open settings file for writing:" << settingsFile.errorString();
        return;
    }

    QJsonObject settingsObj;
    settingsObj["theme"] = currentTheme; // Assuming currentTheme is a member variable holding the current theme

    QJsonDocument settingsDoc(settingsObj);
    settingsFile.write(settingsDoc.toJson());

    settingsFile.close();
}

void MainWindow::on_actionAboutCiphers_triggered()
{
    QString aboutCiphersText = QString(
        "Top Ciphers for File Encryption:\n\n"
        "AES-256-GCM: Provides strong encryption with built-in data integrity and authentication. Highly recommended for file encryption due to its security and performance.\n\n"
        "ChaCha20-Poly1305: A secure cipher that is resistant to timing attacks. It is highly efficient on both software and hardware, and is suitable for environments where performance is critical.\n\n"
        "AES-256-CTR: A strong encryption mode suitable for stream encryption. It does not provide data integrity or authentication by itself, so it should be used with additional integrity checks.\n\n"
        "AES-256-CBC: A widely used encryption mode that provides strong encryption but does not include data integrity or authentication. It is suitable for file encryption but should be combined with a message authentication code (MAC) to ensure data integrity.\n\n"
        "Recommendation: For maximum security in file encryption, use AES-256-GCM or ChaCha20-Poly1305, as they provide both strong encryption and built-in data integrity and authentication.");

    QMessageBox::information(this, "About Ciphers", aboutCiphersText);
}

void MainWindow::on_actionAboutKDFs_triggered()
{
    QString aboutKDFsText = QString(
        "Key Derivation Function (KDF) Information:\n\n"
        "Argon2:\n"
        "  - Designed to resist both GPU and ASIC attacks.\n"
        "  - Highly secure and the winner of the Password Hashing Competition (PHC).\n"
        "  - Recommended for new applications requiring strong password hashing.\n\n"
        "Scrypt:\n"
        "  - Designed to be highly memory-intensive, making it resistant to hardware attacks.\n"
        "  - Suitable for environments where memory usage is not a constraint.\n\n"
        "PBKDF2:\n"
        "  - Widely used and well-established.\n"
        "  - Provides basic protection against brute-force attacks by increasing the computation required.\n"
        "  - Recommended for compatibility with older systems and applications.\n\n"
        "Recommendation:\n"
        "For maximum security, Argon2 is the best choice due to its resistance to various types of attacks. "
        "If memory usage is a concern, Scrypt offers a good balance of security and performance. PBKDF2 should "
        "be used primarily for compatibility with existing systems.");

    QMessageBox::information(this, "About KDFs", aboutKDFsText);
}

void MainWindow::on_actionAboutIterations_triggered()
{
    QString aboutIterationsText = QString(
        "About Iterations:\n\n"
        "The number of iterations used in key derivation functions (KDFs) is a critical factor in the security "
        "of the encryption process. Iterations increase the computational effort required to derive the encryption "
        "key, making brute-force attacks more difficult.\n\n"
        "Recommended Iteration Counts:\n"
        "- Argon2: 10 or more iterations. Argon2 is memory-hard, and higher iterations further increase security.\n"
        "- Scrypt: N = 2^20 (1,048,576) or higher. Scrypt is also memory-hard, and high iteration counts make it more resistant to attacks.\n"
        "- PBKDF2: 10,000,000 or more iterations. PBKDF2 relies on high iteration counts to increase security.\n\n"
        "For maximum security, consider using higher iteration counts, especially if performance is not a critical concern.");

    QMessageBox::information(this, "About Iterations", aboutIterationsText);
}

void MainWindow::on_actionSecurityGuide_triggered()
{
    QString securityGuideText = QString(
        "Security Best Practices Guide\n\n"
        "Secure Password Creation:\n"
        "• Use a MINIMUM of 12 characters, preferably 16+ for highly sensitive data\n"
        "• Include uppercase letters, lowercase letters, numbers, and special characters\n"
        "• Avoid dictionary words, names, dates, or predictable patterns\n"
        "• Consider using a passphrase (multiple words with special characters)\n"
        "• Never reuse passwords from other services or applications\n\n"
        
        "File Security:\n"
        "• Store encrypted files in locations only you have access to\n"
        "• Never store encrypted files in shared directories or cloud services that don't use E2E encryption\n"
        "• Keep keyfiles on separate physical devices (USB drive) from encrypted files\n"
        "• Consider using both a password AND keyfile for critical data\n"
        "• NEVER share passwords through email, messaging, or unencrypted channels\n\n"
        
        "Encryption Settings:\n"
        "• For highest security, use AES-256-GCM or ChaCha20-Poly1305 ciphers\n"
        "• Enable HMAC for additional integrity protection\n"
        "• Use Argon2 KDF when available or Scrypt as alternative\n"
        "• Use high iteration counts (10+) for sensitive data\n"
        "• Use tamper evidence features for critical files\n\n"
        
        "Safe Computing Practices:\n"
        "• Keep your device secure and updated with latest security patches\n"
        "• Use a secure, up-to-date operating system\n"
        "• Be aware of physical surroundings when entering passwords\n"
        "• Scan files for malware before encryption/decryption\n"
        "• Close the application when not in use\n\n"
        
        "Emergency Preparation:\n"
        "• Keep secure offline backups of critical encryption keys\n"
        "• Document recovery procedures and store securely\n"
        "• Test recovery process periodically to ensure it works\n"
        "• Consider secure key escrow for organizational use\n\n"
        
        "Remember: The security of your data is only as strong as your weakest practice!"
    );

    QMessageBox::information(this, "Security Guide", securityGuideText);
}

void MainWindow::setupSecurePasswordFields()
{
    // Configure password fields for security
    ui->filePasswordLineEdit->setEchoMode(QLineEdit::Password);
    ui->folderPasswordLineEdit->setEchoMode(QLineEdit::Password);
    ui->diskPasswordLineEdit->setEchoMode(QLineEdit::Password);
    ui->diskConfirmPasswordLineEdit->setEchoMode(QLineEdit::Password);
    
    // Create password strength indicator labels
    QLabel* fileStrengthLabel = new QLabel(this);
    QLabel* folderStrengthLabel = new QLabel(this);
    QLabel* diskStrengthLabel = new QLabel(this);
    
    // Add labels to layouts
    ui->filePasswordLayout->addWidget(fileStrengthLabel);
    ui->folderPasswordLayout->addWidget(folderStrengthLabel);
    ui->standardVolumeLayout->addWidget(diskStrengthLabel);
    
    // Store references as member variables for later use
    filePasswordStrengthLabel = fileStrengthLabel;
    folderPasswordStrengthLabel = folderStrengthLabel;
    diskPasswordStrengthLabel = diskStrengthLabel;
    
    // Enable password strength indicators
    connect(ui->filePasswordLineEdit, &QLineEdit::textChanged, this, &MainWindow::checkPasswordStrength);
    connect(ui->folderPasswordLineEdit, &QLineEdit::textChanged, this, &MainWindow::checkPasswordStrength);
    connect(ui->diskPasswordLineEdit, &QLineEdit::textChanged, this, &MainWindow::checkPasswordStrength);
    
    // Set placeholder text with password recommendations
    QString pwdHint = "Enter strong password (min. 12 chars, mix of letters/numbers/symbols)";
    ui->filePasswordLineEdit->setPlaceholderText(pwdHint);
    ui->folderPasswordLineEdit->setPlaceholderText(pwdHint);
    ui->diskPasswordLineEdit->setPlaceholderText(pwdHint);
    ui->diskConfirmPasswordLineEdit->setPlaceholderText("Re-enter password to confirm");
    
    // Disable auto-completion for password fields
    ui->filePasswordLineEdit->setAttribute(Qt::WA_InputMethodEnabled, false);
    ui->folderPasswordLineEdit->setAttribute(Qt::WA_InputMethodEnabled, false);
    ui->diskPasswordLineEdit->setAttribute(Qt::WA_InputMethodEnabled, false);
    ui->diskConfirmPasswordLineEdit->setAttribute(Qt::WA_InputMethodEnabled, false);
    
    // Add "Show Password" checkboxes
    QCheckBox* showFilePassword = new QCheckBox("Show Password", this);
    ui->filePasswordLayout->addWidget(showFilePassword);
    connect(showFilePassword, &QCheckBox::toggled, [this](bool checked) {
        ui->filePasswordLineEdit->setEchoMode(checked ? QLineEdit::Normal : QLineEdit::Password);
    });
    
    QCheckBox* showFolderPassword = new QCheckBox("Show Password", this);
    ui->folderPasswordLayout->addWidget(showFolderPassword);
    connect(showFolderPassword, &QCheckBox::toggled, [this](bool checked) {
        ui->folderPasswordLineEdit->setEchoMode(checked ? QLineEdit::Normal : QLineEdit::Password);
    });
}

void MainWindow::checkPasswordStrength(const QString &password)
{
    // Get the sender object to determine which password field was updated
    QObject* sender = QObject::sender();
    if (!sender) return;
    
    QLabel* strengthLabel = nullptr;
    
    if (sender == ui->filePasswordLineEdit) {
        strengthLabel = filePasswordStrengthLabel;
    } else if (sender == ui->folderPasswordLineEdit) {
        strengthLabel = folderPasswordStrengthLabel;
    } else if (sender == ui->diskPasswordLineEdit) {
        strengthLabel = diskPasswordStrengthLabel;
    }
    
    if (!strengthLabel) return;
    
    // Calculate password strength
    int score = 0;
    
    // Length check (up to 5 points)
    score += qMin(5, password.length() / 2);
    
    // Complexity checks
    bool hasUppercase = false;
    bool hasLowercase = false;
    bool hasDigit = false;
    bool hasSpecial = false;
    
    for (const QChar &c : password) {
        if (c.isUpper()) hasUppercase = true;
        else if (c.isLower()) hasLowercase = true;
        else if (c.isDigit()) hasDigit = true;
        else if (c.isPunct() || c.isSymbol()) hasSpecial = true;
    }
    
    if (hasUppercase) score += 1;
    if (hasLowercase) score += 1;
    if (hasDigit) score += 2;
    if (hasSpecial) score += 3;
    
    // Set color and text based on score
    QString strengthText;
    QString colorStyle;
    
    if (password.isEmpty()) {
        strengthText = "";
        colorStyle = "";
    } else if (score < 6) {
        strengthText = "Very Weak";
        colorStyle = "color: #e74c3c;"; // Red
    } else if (score < 8) {
        strengthText = "Weak";
        colorStyle = "color: #e67e22;"; // Orange
    } else if (score < 10) {
        strengthText = "Moderate";
        colorStyle = "color: #f1c40f;"; // Yellow
    } else if (score < 12) {
        strengthText = "Strong";
        colorStyle = "color: #2ecc71;"; // Green
    } else {
        strengthText = "Very Strong";
        colorStyle = "color: #27ae60;"; // Dark Green
    }
    
    strengthLabel->setText(strengthText);
    strengthLabel->setStyleSheet(colorStyle);
}

void MainWindow::on_cryptoProviderComboBox_currentIndexChanged(const QString &providerName)
{
    if (!providerName.isEmpty())
    {
        encryptionEngine.setProvider(providerName);

        // Store current selections if possible
        QString currentFileAlgo = ui->fileAlgorithmComboBox->currentText();
        QString currentFolderAlgo = ui->folderAlgorithmComboBox->currentText();
        QString currentDiskAlgo = ui->diskAlgorithmComboBox->currentText();
        QString currentFileKDF = ui->kdfComboBox->currentText();
        QString currentFolderKDF = ui->folderKdfComboBox->currentText();
        QString currentDiskKDF = ui->diskKdfComboBox->currentText();

        // Update available algorithms and KDFs based on the selected provider
        QStringList algorithms = encryptionEngine.supportedCiphers();
        ui->fileAlgorithmComboBox->clear();
        ui->folderAlgorithmComboBox->clear();
        ui->diskAlgorithmComboBox->clear();
        ui->fileAlgorithmComboBox->addItems(algorithms);
        ui->folderAlgorithmComboBox->addItems(algorithms);
        ui->diskAlgorithmComboBox->addItems(algorithms);

        QStringList kdfs = encryptionEngine.supportedKDFs();
        ui->kdfComboBox->clear();
        ui->folderKdfComboBox->clear();
        ui->diskKdfComboBox->clear();
        ui->kdfComboBox->addItems(kdfs);
        ui->folderKdfComboBox->addItems(kdfs);
        ui->diskKdfComboBox->addItems(kdfs);

        // Try to restore previous selections if they're available in the new provider
        if (algorithms.contains(currentFileAlgo))
            ui->fileAlgorithmComboBox->setCurrentText(currentFileAlgo);

        if (algorithms.contains(currentFolderAlgo))
            ui->folderAlgorithmComboBox->setCurrentText(currentFolderAlgo);
            
        if (algorithms.contains(currentDiskAlgo))
            ui->diskAlgorithmComboBox->setCurrentText(currentDiskAlgo);

        if (kdfs.contains(currentFileKDF))
            ui->kdfComboBox->setCurrentText(currentFileKDF);

        if (kdfs.contains(currentFolderKDF))
            ui->folderKdfComboBox->setCurrentText(currentFolderKDF);
            
        if (kdfs.contains(currentDiskKDF))
            ui->diskKdfComboBox->setCurrentText(currentDiskKDF);

        // Update hardware acceleration status
        checkHardwareAcceleration();

        // Show provider capabilities in the status bar
        QString capabilitiesMessage = QString("Provider: %1 | Ciphers: %2 | KDFs: %3")
                                          .arg(providerName)
                                          .arg(algorithms.join(", "))
                                          .arg(kdfs.join(", "));

        statusBar()->showMessage(capabilitiesMessage, 5000);
    }
}

void MainWindow::showProviderCapabilities()
{
    QString providerName = encryptionEngine.currentProvider();
    if (providerName.isEmpty())
    {
        return;
    }

    QStringList algorithms = encryptionEngine.supportedCiphers();
    QStringList kdfs = encryptionEngine.supportedKDFs();

    QString message = QString(
                          "Current Crypto Provider: %1\n\n"
                          "Supported Ciphers:\n%2\n\n"
                          "Supported KDFs:\n%3\n\n"
                          "Hardware Acceleration: %4")
                          .arg(providerName)
                          .arg(algorithms.join(", "))
                          .arg(kdfs.join(", "))
                          .arg(encryptionEngine.isHardwareAccelerationSupported() ? "Supported" : "Not supported");

    QMessageBox::information(this, "Provider Capabilities", message);
}
