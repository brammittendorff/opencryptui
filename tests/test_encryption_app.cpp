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

    if (!QTest::qWaitFor([&]() { return QFileInfo::exists(encryptedFilePath); }, 15000)) {
        qDebug() << "Encryption failed or timed out for" << cipher << "with" << kdf;
        return false;
    }
    qDebug() << "Encrypted file created:" << encryptedFilePath;

    // Set up decryption parameters
    filePathInput->setText(encryptedFilePath);
    passwordInput->setText("testpassword");
    qDebug() << "Decryption parameters set up";

    // Decrypt
    qDebug() << "Clicking decrypt button";
    QTest::mouseClick(decryptButton, Qt::LeftButton);

    if (!QTest::qWaitFor([&]() { return QFileInfo::exists(testFilePath); }, 15000)) {
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
    qDebug() << "Test files cleaned up";

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
    foreach (QWidget *widget, QApplication::topLevelWidgets()) {
        if (widget->isVisible()) {
            QMessageBox *msgBox = qobject_cast<QMessageBox*>(widget);
            if (msgBox) {
                qDebug() << "Found QMessageBox with title:" << msgBox->windowTitle();
                if (msgBox->isVisible()) {
                    qDebug() << "QMessageBox is visible";

                    QAbstractButton *okButton = msgBox->button(QMessageBox::Ok);
                    if (okButton) {
                        qDebug() << "Clicking OK button";
                        QTest::mouseClick(okButton, Qt::LeftButton);
                        return;
                    } else {
                        qDebug() << "OK button not found in QMessageBox";
                    }
                } else {
                    qDebug() << "QMessageBox is not visible";
                }
            }
        }
    }

    qDebug() << "No QMessageBox found";
}

QTEST_MAIN(TestOpenCryptUI)
#include "test_encryption_app.moc"
