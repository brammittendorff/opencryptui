#include <QtTest/QtTest>
#include <QApplication>
#include <QMainWindow>
#include <QLineEdit>
#include <QPushButton>
#include <QFileInfo>
#include <QMessageBox>
#include <QListWidget>
#include <QComboBox>
#include "mainwindow.h"
#include <QTimer>
#include <QWindow>
#include <QCheckBox>

class TestOpenCryptUI : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void testEncryptDecrypt();
    void testEncryptDecryptWithKeyfile();
    void testAllCiphersAndKDFs();
    void cleanupTestCase();
    void closeMessageBoxes();
    void testCustomChaCha20Implementation();

private:
    QTimer *messageBoxTimer;
    MainWindow *mainWindow;
    QString createTestFile(const QString &content);
    QString createKeyfile(const QString &content);
    bool encryptAndDecrypt(const QString &cipher, const QString &kdf, bool useKeyfile);
};

void TestOpenCryptUI::initTestCase()
{
    mainWindow = new MainWindow();
    mainWindow->show();

    messageBoxTimer = new QTimer(this);
    connect(messageBoxTimer, &QTimer::timeout, this, &TestOpenCryptUI::closeMessageBoxes);
    messageBoxTimer->start(1000);
}

void TestOpenCryptUI::cleanupTestCase()
{
    messageBoxTimer->stop();
    delete mainWindow;
}

QString TestOpenCryptUI::createTestFile(const QString &content)
{
    QString testFilePath = QDir::currentPath() + "/test.txt";
    QFile testFile(testFilePath);
    if (!testFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        qDebug() << "Failed to open test file for writing";
        return QString();
    }
    QTextStream out(&testFile);
    out << content;
    testFile.close();
    qDebug() << "Test file created with content '" << content << "' at" << testFilePath;
    return testFilePath;
}

QString TestOpenCryptUI::createKeyfile(const QString &content)
{
    QString keyfilePath = QDir::currentPath() + "/keyfile.txt";
    QFile keyfile(keyfilePath);
    if (!keyfile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        qDebug() << "Failed to open keyfile for writing";
        return QString();
    }
    QTextStream out(&keyfile);
    out << content;
    keyfile.close();
    qDebug() << "Keyfile created with content '" << content << "' at" << keyfilePath;
    return keyfilePath;
}

void TestOpenCryptUI::testEncryptDecrypt()
{
    QLineEdit *filePathInput = mainWindow->findChild<QLineEdit*>("filePathLineEdit");
    QLineEdit *passwordInput = mainWindow->findChild<QLineEdit*>("filePasswordLineEdit");
    QPushButton *encryptButton = mainWindow->findChild<QPushButton*>("fileEncryptButton");
    QPushButton *decryptButton = mainWindow->findChild<QPushButton*>("fileDecryptButton");

    QVERIFY(filePathInput);
    QVERIFY(passwordInput);
    QVERIFY(encryptButton);
    QVERIFY(decryptButton);

    QString testFilePath = QDir::currentPath() + "/test.txt";
    QString encryptedFilePath = QDir::currentPath() + "/test.txt.enc";

    QFile::remove(testFilePath);
    QFile::remove(encryptedFilePath);

    QFile testFile(testFilePath);
    QVERIFY(testFile.open(QIODevice::WriteOnly | QIODevice::Text));
    QTextStream out(&testFile);
    out << "test";
    testFile.close();

    qDebug() << "Test file created with content 'test' at" << testFilePath;

    filePathInput->setText(testFilePath);
    passwordInput->setText("testpassword");
    QTest::mouseClick(encryptButton, Qt::LeftButton);

    QTRY_VERIFY_WITH_TIMEOUT(QFileInfo::exists(encryptedFilePath), 15000);

    QVERIFY(QFileInfo::exists(encryptedFilePath));

    QFile encryptedFile(encryptedFilePath);
    QVERIFY(encryptedFile.open(QIODevice::ReadOnly));
    QByteArray encryptedContent = encryptedFile.readAll();
    qDebug() << "Encrypted file content (hex):" << encryptedContent.toHex();
    encryptedFile.close();

    filePathInput->setText(encryptedFilePath);
    passwordInput->setText("testpassword");
    QTest::mouseClick(decryptButton, Qt::LeftButton);

    QTRY_VERIFY_WITH_TIMEOUT(QFileInfo::exists(testFilePath), 15000);

    QVERIFY(QFileInfo::exists(testFilePath));

    QFile decryptedFile(testFilePath);
    QVERIFY(decryptedFile.open(QIODevice::ReadOnly | QIODevice::Text));
    QTextStream in(&decryptedFile);
    QString content = in.readAll().trimmed();
    qDebug() << "Decrypted file content:" << content;
    QCOMPARE(content, QString("test"));

    QFile::remove(testFilePath);
    QFile::remove(encryptedFilePath);
}

void TestOpenCryptUI::testEncryptDecryptWithKeyfile()
{
    QLineEdit *filePathInput = mainWindow->findChild<QLineEdit*>("filePathLineEdit");
    QLineEdit *passwordInput = mainWindow->findChild<QLineEdit*>("filePasswordLineEdit");
    QPushButton *encryptButton = mainWindow->findChild<QPushButton*>("fileEncryptButton");
    QPushButton *decryptButton = mainWindow->findChild<QPushButton*>("fileDecryptButton");
    QListWidget *keyfileListWidget = mainWindow->findChild<QListWidget*>("fileKeyfileListWidget");

    QVERIFY(filePathInput);
    QVERIFY(passwordInput);
    QVERIFY(encryptButton);
    QVERIFY(decryptButton);
    QVERIFY(keyfileListWidget);

    QString testFilePath = createTestFile("test with keyfile");
    QString encryptedFilePath = testFilePath + ".enc";
    QString keyfilePath = createKeyfile("secret key content");

    // Encryption with keyfile
    filePathInput->setText(testFilePath);
    passwordInput->setText("testpassword");
    keyfileListWidget->addItem(keyfilePath);
    QTest::mouseClick(encryptButton, Qt::LeftButton);

    QTRY_VERIFY_WITH_TIMEOUT(QFileInfo::exists(encryptedFilePath), 15000);

    QFile encryptedFile(encryptedFilePath);
    QVERIFY(encryptedFile.open(QIODevice::ReadOnly));
    QByteArray encryptedContent = encryptedFile.readAll();
    qDebug() << "Encrypted file content (hex):" << encryptedContent.toHex();
    encryptedFile.close();

    // Decryption with keyfile
    filePathInput->setText(encryptedFilePath);
    passwordInput->setText("testpassword");
    QTest::mouseClick(decryptButton, Qt::LeftButton);

    QTRY_VERIFY_WITH_TIMEOUT(QFileInfo::exists(testFilePath), 15000);

    QFile decryptedFile(testFilePath);
    QVERIFY(decryptedFile.open(QIODevice::ReadOnly | QIODevice::Text));
    QTextStream in(&decryptedFile);
    QString content = in.readAll().trimmed();
    qDebug() << "Decrypted file content:" << content;
    QCOMPARE(content, QString("test with keyfile"));

    QFile::remove(testFilePath);
    QFile::remove(encryptedFilePath);
    QFile::remove(keyfilePath);
}

bool TestOpenCryptUI::encryptAndDecrypt(const QString &cipher, const QString &kdf, bool useKeyfile)
{
    qDebug() << "Starting encryptAndDecrypt test for" << cipher << "with" << kdf << (useKeyfile ? "and keyfile" : "");

    QLineEdit *filePathInput = mainWindow->findChild<QLineEdit*>("filePathLineEdit");
    QLineEdit *passwordInput = mainWindow->findChild<QLineEdit*>("filePasswordLineEdit");
    QPushButton *encryptButton = mainWindow->findChild<QPushButton*>("fileEncryptButton");
    QPushButton *decryptButton = mainWindow->findChild<QPushButton*>("fileDecryptButton");
    QComboBox *algorithmComboBox = mainWindow->findChild<QComboBox*>("fileAlgorithmComboBox");
    QComboBox *kdfComboBox = mainWindow->findChild<QComboBox*>("kdfComboBox");
    QListWidget *keyfileListWidget = mainWindow->findChild<QListWidget*>("fileKeyfileListWidget");

    if (!filePathInput || !passwordInput || !encryptButton || !decryptButton || 
        !algorithmComboBox || !kdfComboBox || !keyfileListWidget) {
        qDebug() << "Failed to find all required UI elements";
        return false;
    }

    QString testContent = "Test content for " + cipher + " with " + kdf;
    QString testFilePath = createTestFile(testContent);
    if (testFilePath.isEmpty()) {
        qDebug() << "Failed to create test file";
        return false;
    }

    QString encryptedFilePath = testFilePath + ".enc";
    QString keyfilePath;

    if (useKeyfile) {
        keyfilePath = createKeyfile("Secret key for " + cipher);
        if (keyfilePath.isEmpty()) {
            qDebug() << "Failed to create keyfile";
            return false;
        }
        keyfileListWidget->addItem(keyfilePath);
        qDebug() << "Keyfile created and added to list widget";
    } else {
        keyfileListWidget->clear();
        qDebug() << "Keyfile list widget cleared";
    }

    // Set up encryption parameters
    filePathInput->setText(testFilePath);
    passwordInput->setText("testpassword");
    algorithmComboBox->setCurrentText(cipher);
    kdfComboBox->setCurrentText(kdf);
    qDebug() << "Encryption parameters set up";

    // Encrypt
    qDebug() << "Clicking encrypt button";
    QTest::mouseClick(encryptButton, Qt::LeftButton);

    if (!QTest::qWaitFor([&]() { return QFileInfo::exists(encryptedFilePath); }, 30000)) {  // Increase timeout for debugging
        qDebug() << "Encryption failed or timed out for" << cipher << "with" << kdf;
        return false;
    }
    qDebug() << "Encrypted file created:" << encryptedFilePath;

    // Log the encrypted content
    QFile encryptedFile(encryptedFilePath);
    if (encryptedFile.open(QIODevice::ReadOnly)) {
        QByteArray encryptedContent = encryptedFile.readAll();
        qDebug() << "Encrypted file content (hex):" << encryptedContent.toHex();
        encryptedFile.close();
    } else {
        qDebug() << "Failed to open encrypted file";
        return false;
    }

    // Set up decryption parameters
    filePathInput->setText(encryptedFilePath);
    passwordInput->setText("testpassword");
    qDebug() << "Decryption parameters set up";

    // Decrypt
    qDebug() << "Clicking decrypt button";
    QTest::mouseClick(decryptButton, Qt::LeftButton);

    if (!QTest::qWaitFor([&]() { return QFileInfo::exists(testFilePath); }, 30000)) {  // Increase timeout for debugging
        qDebug() << "Decryption failed or timed out for" << cipher << "with" << kdf;
        return false;
    }
    qDebug() << "Decrypted file created:" << testFilePath;

    // Verify decrypted content
    QFile decryptedFile(testFilePath);
    if (!decryptedFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qDebug() << "Failed to open decrypted file";
        return false;
    }
    QTextStream in(&decryptedFile);
    QString decryptedContent = in.readAll().trimmed();
    decryptedFile.close();

    if (decryptedContent != testContent) {
        qDebug() << "Decrypted content does not match original for" << cipher << "with" << kdf;
        qDebug() << "Expected:" << testContent;
        qDebug() << "Actual:" << decryptedContent;
        return false;
    }
    qDebug() << "Decrypted content matches original";

    qDebug() << "Test for" << cipher << "with" << kdf << (useKeyfile ? "and keyfile" : "") << "PASSED";

    // Clean up
    QFile::remove(testFilePath);
    QFile::remove(encryptedFilePath);
    if (useKeyfile) {
        QFile::remove(keyfilePath);
    }

    return true;
}

void TestOpenCryptUI::testAllCiphersAndKDFs()
{
    QStringList ciphers = {"AES-256-GCM", "ChaCha20-Poly1305", "AES-256-CTR", "AES-256-CBC"};
    QStringList kdfs = {"Argon2", "Scrypt", "PBKDF2"};

    for (const QString &cipher : ciphers) {
        for (const QString &kdf : kdfs) {
            QVERIFY2(encryptAndDecrypt(cipher, kdf, false), qPrintable(QString("Failed for %1 with %2 without keyfile").arg(cipher, kdf)));
            QVERIFY2(encryptAndDecrypt(cipher, kdf, true), qPrintable(QString("Failed for %1 with %2 with keyfile").arg(cipher, kdf)));
        }
    }
}

void TestOpenCryptUI::closeMessageBoxes()
{
    // Iterate through all top-level widgets
    foreach (QWidget *widget, QApplication::topLevelWidgets()) {
        // Check if the widget is a visible QMessageBox
        QMessageBox *msgBox = qobject_cast<QMessageBox*>(widget);
        if (msgBox && msgBox->isVisible()) {
            qDebug() << "Found and closing QMessageBox with title:" << msgBox->windowTitle();

            // Find the OK button and click it
            QAbstractButton *okButton = msgBox->button(QMessageBox::Ok);
            if (okButton) {
                qDebug() << "Clicking OK button";
                QTest::mouseClick(okButton, Qt::LeftButton);
            } else {
                qDebug() << "OK button not found in QMessageBox";
            }
        }
    }
}

void TestOpenCryptUI::testCustomChaCha20Implementation()
{
    qDebug() << "Starting test for custom ChaCha20 implementation";

    // Find UI elements
    QLineEdit *filePathInput = mainWindow->findChild<QLineEdit*>("filePathLineEdit");
    QLineEdit *passwordInput = mainWindow->findChild<QLineEdit*>("filePasswordLineEdit");
    QPushButton *encryptButton = mainWindow->findChild<QPushButton*>("fileEncryptButton");
    QPushButton *decryptButton = mainWindow->findChild<QPushButton*>("fileDecryptButton");
    QComboBox *algorithmComboBox = mainWindow->findChild<QComboBox*>("fileAlgorithmComboBox");
    QCheckBox *customImplCheckBox = mainWindow->findChild<QCheckBox*>("fileCustomImplCheckBox");
    
    QVERIFY(filePathInput);
    QVERIFY(passwordInput);
    QVERIFY(encryptButton);
    QVERIFY(decryptButton);
    QVERIFY(algorithmComboBox);
    QVERIFY(customImplCheckBox);
    
    // Create test file
    QString testContent = "Test content for custom ChaCha20 implementation";
    QString testFilePath = createTestFile(testContent);
    QVERIFY(!testFilePath.isEmpty());
    
    QString encryptedFilePath = testFilePath + ".cus"; // .cus extension for custom impl
    
    // Set up encryption parameters
    filePathInput->setText(testFilePath);
    passwordInput->setText("customPassword123");
    algorithmComboBox->setCurrentText("ChaCha20-Poly1305");
    customImplCheckBox->setChecked(true);  // Enable custom implementation
    qDebug() << "Encryption parameters set up for custom ChaCha20";
    
    // Encrypt with custom implementation
    qDebug() << "Clicking encrypt button with custom implementation enabled";
    QTest::mouseClick(encryptButton, Qt::LeftButton);
    
    // Wait for encrypted file to be created
    if (!QTest::qWaitFor([&]() { return QFileInfo::exists(encryptedFilePath); }, 30000)) {
        QFAIL("Encryption with custom ChaCha20 failed or timed out");
    }
    qDebug() << "Encrypted file created with custom implementation:" << encryptedFilePath;
    
    // Verify encrypted file exists and is different from original
    QFile encryptedFile(encryptedFilePath);
    QVERIFY(encryptedFile.open(QIODevice::ReadOnly));
    QByteArray encryptedContent = encryptedFile.readAll();
    qDebug() << "Encrypted file content (hex):" << encryptedContent.toHex().left(100) << "...";
    encryptedFile.close();
    
    // Make sure it's actually encrypted (not plaintext)
    QVERIFY(!encryptedContent.contains(testContent.toUtf8()));
    
    // Now decrypt
    filePathInput->setText(encryptedFilePath);
    passwordInput->setText("customPassword123");
    customImplCheckBox->setChecked(true);  // Keep custom implementation enabled
    qDebug() << "Decryption parameters set up for custom ChaCha20";
    
    // Decrypt with custom implementation
    qDebug() << "Clicking decrypt button with custom implementation enabled";
    QTest::mouseClick(decryptButton, Qt::LeftButton);
    
    // Wait for decrypted file to be created
    if (!QTest::qWaitFor([&]() { return QFileInfo::exists(testFilePath); }, 30000)) {
        QFAIL("Decryption with custom ChaCha20 failed or timed out");
    }
    qDebug() << "Decrypted file created with custom implementation:" << testFilePath;
    
    // Verify decrypted content matches original
    QFile decryptedFile(testFilePath);
    QVERIFY(decryptedFile.open(QIODevice::ReadOnly | QIODevice::Text));
    QTextStream in(&decryptedFile);
    QString decryptedContent = in.readAll().trimmed();
    decryptedFile.close();
    
    qDebug() << "Decrypted content: " << decryptedContent;
    qDebug() << "Original content: " << testContent;
    QCOMPARE(decryptedContent, testContent);
    
    qDebug() << "Test for custom ChaCha20 implementation PASSED";
    
    // Clean up
    QFile::remove(testFilePath);
    QFile::remove(encryptedFilePath);
}

QTEST_MAIN(TestOpenCryptUI)
#include "test_encryption_app.moc"
