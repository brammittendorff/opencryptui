#include <QtTest/QtTest>
#include <QApplication>
#include <QMainWindow>
#include <QLineEdit>
#include <QPushButton>
#include <QFileInfo>
#include <QMessageBox>
#include "mainwindow.h"
#include <QTimer>
#include <QWindow>

class TestEncryptionApp : public QObject
{
    Q_OBJECT

private slots:
    void testEncryptDecrypt();
    void closeMessageBoxes();

private:
    QTimer *messageBoxTimer;
};

void TestEncryptionApp::testEncryptDecrypt()
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
    connect(messageBoxTimer, &QTimer::timeout, this, &TestEncryptionApp::closeMessageBoxes);
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

void TestEncryptionApp::closeMessageBoxes()
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

QTEST_MAIN(TestEncryptionApp)
#include "test_encryption_app.moc"
