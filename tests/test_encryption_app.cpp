#include <QtTest/QtTest>
#include <QApplication>
#include <QMainWindow>
#include <QLineEdit>
#include <QPushButton>
#include <QFileInfo>
#include <QMessageBox>
#include <QListWidget>
#include "mainwindow.h"
#include <QTimer>
#include <QWindow>

class TestOpenCryptUI : public QObject
{
    Q_OBJECT

private slots:
    void testEncryptDecrypt();
    void testEncryptDecryptWithKeyfile();
    void closeMessageBoxes();

private:
    QTimer *messageBoxTimer;
    QString createTestFile(const QString &content);
    QString createKeyfile(const QString &content);
};

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
    MainWindow mainWindow;
    mainWindow.show();

    QLineEdit *filePathInput = mainWindow.findChild<QLineEdit*>("filePathLineEdit");
    QLineEdit *passwordInput = mainWindow.findChild<QLineEdit*>("filePasswordLineEdit");
    QPushButton *encryptButton = mainWindow.findChild<QPushButton*>("fileEncryptButton");
    QPushButton *decryptButton = mainWindow.findChild<QPushButton*>("fileDecryptButton");

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

    // Log the file creation
    qDebug() << "Test file created with content 'test' at" << testFilePath;

    // Set up for message box handling
    messageBoxTimer = new QTimer(this);
    connect(messageBoxTimer, &QTimer::timeout, this, &TestOpenCryptUI::closeMessageBoxes);
    messageBoxTimer->start(1000);

    filePathInput->setText(testFilePath);
    passwordInput->setText("testpassword");
    QTest::mouseClick(encryptButton, Qt::LeftButton);

    QTRY_VERIFY_WITH_TIMEOUT(QFileInfo::exists(encryptedFilePath), 15000);

    QVERIFY(QFileInfo::exists(encryptedFilePath));

    // Log encrypted file content
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

    // Log decrypted file content
    QFile decryptedFile(testFilePath);
    QVERIFY(decryptedFile.open(QIODevice::ReadOnly | QIODevice::Text));
    QTextStream in(&decryptedFile);
    QString content = in.readAll().trimmed();
    qDebug() << "Decrypted file content:" << content;
    QCOMPARE(content, QString("test"));

    QFile::remove(testFilePath);
    QFile::remove(encryptedFilePath);

    messageBoxTimer->stop();
}

void TestOpenCryptUI::testEncryptDecryptWithKeyfile()
{
    MainWindow mainWindow;
    mainWindow.show();

    QLineEdit *filePathInput = mainWindow.findChild<QLineEdit*>("filePathLineEdit");
    QLineEdit *passwordInput = mainWindow.findChild<QLineEdit*>("filePasswordLineEdit");
    QPushButton *encryptButton = mainWindow.findChild<QPushButton*>("fileEncryptButton");
    QPushButton *decryptButton = mainWindow.findChild<QPushButton*>("fileDecryptButton");
    QListWidget *keyfileListWidget = mainWindow.findChild<QListWidget*>("fileKeyfileListWidget");

    QVERIFY(filePathInput);
    QVERIFY(passwordInput);
    QVERIFY(encryptButton);
    QVERIFY(decryptButton);
    QVERIFY(keyfileListWidget);

    QString testFilePath = createTestFile("test with keyfile");
    QString encryptedFilePath = testFilePath + ".enc";
    QString keyfilePath = createKeyfile("secret key content");

    // Set up for message box handling
    messageBoxTimer = new QTimer(this);
    connect(messageBoxTimer, &QTimer::timeout, this, &TestOpenCryptUI::closeMessageBoxes);
    messageBoxTimer->start(1000);

    // Encryption with keyfile
    filePathInput->setText(testFilePath);
    passwordInput->setText("testpassword");
    keyfileListWidget->addItem(keyfilePath);
    QTest::mouseClick(encryptButton, Qt::LeftButton);

    QTRY_VERIFY_WITH_TIMEOUT(QFileInfo::exists(encryptedFilePath), 15000);

    // Log encrypted file content
    QFile encryptedFile(encryptedFilePath);
    QVERIFY(encryptedFile.open(QIODevice::ReadOnly));
    QByteArray encryptedContent = encryptedFile.readAll();
    qDebug() << "Encrypted file content (hex):" << encryptedContent.toHex();
    encryptedFile.close();

    // Decryption with keyfile
    filePathInput->setText(encryptedFilePath);
    passwordInput->setText("testpassword");
    // Keyfile should still be in the list
    QTest::mouseClick(decryptButton, Qt::LeftButton);

    QTRY_VERIFY_WITH_TIMEOUT(QFileInfo::exists(testFilePath), 15000);

    // Verify decrypted content
    QFile decryptedFile(testFilePath);
    QVERIFY(decryptedFile.open(QIODevice::ReadOnly | QIODevice::Text));
    QTextStream in(&decryptedFile);
    QString content = in.readAll().trimmed();
    qDebug() << "Decrypted file content:" << content;
    QCOMPARE(content, QString("test with keyfile"));

    // Clean up
    QFile::remove(testFilePath);
    QFile::remove(encryptedFilePath);
    QFile::remove(keyfilePath);

    messageBoxTimer->stop();
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
