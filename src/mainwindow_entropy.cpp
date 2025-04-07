#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QBuffer>
#include <QThread>
#include "logging/secure_logger.h"
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
#include <QtConcurrent/QtConcurrent>
#include <QFuture>
#include <QFutureWatcher>
#include <QVBoxLayout>
#include <QDateTime>
#include <QProcess>
#include <QRandomGenerator>
#include <QDebug>

// Setup entropy monitoring UI in each tab
void MainWindow::setupEntropyMonitoring()
{
    // Create entropy monitoring UI components
    createEntropyMonitoringUI(ui->diskTab, "disk");
    createEntropyMonitoringUI(ui->fileTab, "file");
    createEntropyMonitoringUI(ui->folderTab, "folder");
    
    // Add text description to benchmark tab about entropy
    QLabel* entropyBenchmarkLabel = new QLabel(ui->benchmarkTab);
    entropyBenchmarkLabel->setText("Entropy Health Monitoring provides real-time security metrics about the quality of random numbers "
                                 "used for encryption. The system continuously tests entropy sources for government-level security.");
    entropyBenchmarkLabel->setWordWrap(true);
    QFont boldFont = entropyBenchmarkLabel->font();
    boldFont.setBold(true);
    entropyBenchmarkLabel->setFont(boldFont);
    
    // Insert at the top of the benchmark tab
    QVBoxLayout* benchmarkLayout = qobject_cast<QVBoxLayout*>(ui->benchmarkTab->layout());
    if (benchmarkLayout) {
        benchmarkLayout->insertWidget(0, entropyBenchmarkLabel);
    }
    
    // Start entropy monitoring with a timer
    QTimer* entropyTimer = new QTimer(this);
    connect(entropyTimer, &QTimer::timeout, this, &MainWindow::updateEntropyDisplays);
    entropyTimer->start(5000); // Update every 5 seconds
    
    // Run initial entropy test
    QTimer::singleShot(500, this, &MainWindow::updateEntropyHealth);
}

// Create entropy monitoring UI components for a tab
void MainWindow::createEntropyMonitoringUI(QWidget* tabWidget, const QString& prefix)
{
    // Create the group box for entropy monitoring
    QGroupBox* entropyGroup = new QGroupBox("Entropy Health Monitoring", tabWidget);
    
    // Create layout for entropy monitor
    QVBoxLayout* entropyLayout = new QVBoxLayout(entropyGroup);
    
    // Status indicator
    QHBoxLayout* statusLayout = new QHBoxLayout();
    QLabel* statusLabel = new QLabel("Status:", entropyGroup);
    QLabel* statusValueLabel = new QLabel("Initializing...", entropyGroup);
    statusValueLabel->setObjectName(prefix + "EntropyStatusLabel");
    
    // Make status value bold
    QFont boldFont = statusValueLabel->font();
    boldFont.setBold(true);
    statusValueLabel->setFont(boldFont);
    
    statusLayout->addWidget(statusLabel);
    statusLayout->addWidget(statusValueLabel, 1);
    
    // Hardware RNG indicator
    QHBoxLayout* hardwareLayout = new QHBoxLayout();
    QLabel* hardwareLabel = new QLabel("Hardware RNG:", entropyGroup);
    QLabel* hardwareValueLabel = new QLabel("Checking...", entropyGroup);
    hardwareValueLabel->setObjectName(prefix + "HardwareRngLabel");
    hardwareLayout->addWidget(hardwareLabel);
    hardwareLayout->addWidget(hardwareValueLabel, 1);
    
    // Entropy quality progress bar
    QHBoxLayout* qualityLayout = new QHBoxLayout();
    QLabel* qualityLabel = new QLabel("Entropy Quality:", entropyGroup);
    QProgressBar* qualityProgress = new QProgressBar(entropyGroup);
    qualityProgress->setObjectName(prefix + "EntropyQualityBar");
    qualityProgress->setRange(0, 100);
    qualityProgress->setValue(0);
    qualityProgress->setTextVisible(true);
    qualityProgress->setFormat("%v%");
    qualityLayout->addWidget(qualityLabel);
    qualityLayout->addWidget(qualityProgress, 1);
    
    // Bit distribution indicator
    QHBoxLayout* bitsLayout = new QHBoxLayout();
    QLabel* bitsLabel = new QLabel("Bit Distribution:", entropyGroup);
    QProgressBar* bitsProgress = new QProgressBar(entropyGroup);
    bitsProgress->setObjectName(prefix + "BitDistributionBar");
    bitsProgress->setRange(0, 100);
    bitsProgress->setValue(50);
    bitsProgress->setTextVisible(true);
    bitsProgress->setFormat("%v%");
    bitsLayout->addWidget(bitsLabel);
    bitsLayout->addWidget(bitsProgress, 1);
    
    // Last check time
    QHBoxLayout* timeLayout = new QHBoxLayout();
    QLabel* timeLabel = new QLabel("Last Test:", entropyGroup);
    QLabel* timeValueLabel = new QLabel("Never", entropyGroup);
    timeValueLabel->setObjectName(prefix + "LastTestTimeLabel");
    timeLayout->addWidget(timeLabel);
    timeLayout->addWidget(timeValueLabel, 1);
    
    // Test entropy button
    QPushButton* testButton = new QPushButton("Run Entropy Test", entropyGroup);
    testButton->setObjectName(prefix + "TestEntropyButton");
    connect(testButton, &QPushButton::clicked, this, &MainWindow::runEntropyTest);
    
    // Add layouts to the entropy group
    entropyLayout->addLayout(statusLayout);
    entropyLayout->addLayout(hardwareLayout);
    entropyLayout->addLayout(qualityLayout);
    entropyLayout->addLayout(bitsLayout);
    entropyLayout->addLayout(timeLayout);
    entropyLayout->addWidget(testButton);
    
    // Add the entropy group to the tab's layout
    QVBoxLayout* tabLayout = qobject_cast<QVBoxLayout*>(tabWidget->layout());
    if (tabLayout) {
        tabLayout->insertWidget(tabLayout->count()-1, entropyGroup);
    }
}

// Update entropy health status periodically
void MainWindow::updateEntropyHealth()
{
    // Run the entropy test in the background
    QFuture<EncryptionEngine::EntropyTestResult> future = QtConcurrent::run(&encryptionEngine, 
                                                                          &EncryptionEngine::performEntropyTest, 1024);
    
    // Connect to a watcher to handle the result
    QFutureWatcher<EncryptionEngine::EntropyTestResult>* watcher = 
        new QFutureWatcher<EncryptionEngine::EntropyTestResult>(this);
    
    connect(watcher, &QFutureWatcher<EncryptionEngine::EntropyTestResult>::finished, 
            [this, watcher]() {
                // Get the result
                EncryptionEngine::EntropyTestResult result = watcher->result();
                
                // Show a notification if entropy quality is poor
                if (!result.passed) {
                    QMessageBox::warning(this, "Entropy Warning", 
                                       "The quality of random numbers used for encryption may be compromised.\n\n"
                                       "Test failed: " + result.testName + "\n" + result.details);
                }
                
                // Update UI elements
                updateEntropyDisplays();
                
                // Clean up the watcher
                watcher->deleteLater();
            });
    
    watcher->setFuture(future);
}

// Run an on-demand entropy test
void MainWindow::runEntropyTest()
{
    // Show a busy cursor
    QApplication::setOverrideCursor(Qt::WaitCursor);
    
    // Run the test with larger sample
    EncryptionEngine::EntropyTestResult result = encryptionEngine.performEntropyTest(4096);
    
    // Restore the cursor
    QApplication::restoreOverrideCursor();
    
    // Show the results
    QString resultMessage;
    
    if (result.passed) {
        resultMessage = "All entropy tests passed successfully.\n\n";
    } else {
        resultMessage = "Entropy test failed: " + result.testName + "\n" + result.details + "\n\n";
    }
    
    resultMessage += QString("Bit frequency: %1 (ideal: 0.5)\n").arg(result.bitFrequency);
    resultMessage += QString("Runs value: %1 (expected: 0.1-5.0)\n").arg(result.runsValue);
    resultMessage += QString("Serial correlation: %1 (ideal: 0)\n").arg(result.serialCorrelation);
    resultMessage += QString("Hardware RNG available: %1\n").arg(encryptionEngine.isHardwareRngAvailable() ? "Yes" : "No");
    resultMessage += QString("\nEntropy health score: %1/100").arg(encryptionEngine.getEntropyHealthScore());
    
    // Show the result message
    QMessageBox::information(this, "Entropy Test Results", resultMessage);
    
    // Update the UI
    updateEntropyDisplays();
}

// Update entropy display components in all tabs
void MainWindow::updateEntropyDisplays()
{
    // Get the current entropy status
    QString status = encryptionEngine.getEntropyHealthStatus();
    int score = encryptionEngine.getEntropyHealthScore();
    bool hwRng = encryptionEngine.isHardwareRngAvailable();
    int bitDist = encryptionEngine.getBitDistribution();
    QDateTime lastTest = encryptionEngine.getLastEntropyTestTime();
    
    // Update each tab's entropy display
    updateTabEntropyDisplay("disk", status, score, hwRng, bitDist, lastTest);
    updateTabEntropyDisplay("file", status, score, hwRng, bitDist, lastTest);
    updateTabEntropyDisplay("folder", status, score, hwRng, bitDist, lastTest);
}

// Update a specific tab's entropy display
void MainWindow::updateTabEntropyDisplay(const QString& prefix, 
                                       const QString& status, 
                                       int score, 
                                       bool hwRng, 
                                       int bitDist, 
                                       const QDateTime& lastTest)
{
    // Status label
    QLabel* statusLabel = findChild<QLabel*>(prefix + "EntropyStatusLabel");
    if (statusLabel) {
        statusLabel->setText(status);
        
        // Set color based on status
        if (status == "Good") {
            statusLabel->setStyleSheet("color: green;");
        } else if (status == "Warning") {
            statusLabel->setStyleSheet("color: orange;");
        } else if (status == "Critical") {
            statusLabel->setStyleSheet("color: red;");
        } else {
            statusLabel->setStyleSheet("");
        }
    }
    
    // Hardware RNG label
    QLabel* hwRngLabel = findChild<QLabel*>(prefix + "HardwareRngLabel");
    if (hwRngLabel) {
        hwRngLabel->setText(hwRng ? "Available" : "Not Available");
        hwRngLabel->setStyleSheet(hwRng ? "color: green;" : "color: orange;");
    }
    
    // Quality progress bar
    QProgressBar* qualityBar = findChild<QProgressBar*>(prefix + "EntropyQualityBar");
    if (qualityBar) {
        qualityBar->setValue(score);
        
        // Set color based on score
        if (score >= 80) {
            qualityBar->setStyleSheet("QProgressBar::chunk { background-color: green; }");
        } else if (score >= 60) {
            qualityBar->setStyleSheet("QProgressBar::chunk { background-color: yellow; }");
        } else {
            qualityBar->setStyleSheet("QProgressBar::chunk { background-color: red; }");
        }
    }
    
    // Bit distribution bar
    QProgressBar* bitsBar = findChild<QProgressBar*>(prefix + "BitDistributionBar");
    if (bitsBar) {
        bitsBar->setValue(bitDist);
        
        // Set color based on bit distribution (closest to 50% is best)
        int deviation = std::abs(bitDist - 50);
        if (deviation <= 2) {
            bitsBar->setStyleSheet("QProgressBar::chunk { background-color: green; }");
        } else if (deviation <= 5) {
            bitsBar->setStyleSheet("QProgressBar::chunk { background-color: yellow; }");
        } else {
            bitsBar->setStyleSheet("QProgressBar::chunk { background-color: red; }");
        }
    }
    
    // Last test time
    QLabel* timeLabel = findChild<QLabel*>(prefix + "LastTestTimeLabel");
    if (timeLabel) {
        if (lastTest.isValid()) {
            timeLabel->setText(lastTest.toString("yyyy-MM-dd hh:mm:ss"));
        } else {
            timeLabel->setText("Never");
        }
    }
}