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
    // Start your main application
    MainWindow mainWindow;
    mainWindow.show();

    // Find the widgets
    QLineEdit *filePathInput = mainWindow.findChild<QLineEdit*>("filePathLineEdit");
    QLineEdit *passwordInput = mainWindow.findChild<QLineEdit*>("filePasswordLineEdit");
    QPushButton *encryptButton = mainWindow.findChild<QPushButton*>("fileEncryptButton");
    QPushButton *decryptButton = mainWindow.findChild<QPushButton*>("fileDecryptButton");

    QVERIFY(filePathInput);
    QVERIFY(passwordInput);
    QVERIFY(encryptButton);
    QVERIFY(decryptButton);

    // Create a test file
    QFile testFile(QDir::currentPath() + "/test.txt");
    QVERIFY(testFile.open(QIODevice::WriteOnly | QIODevice::Text));
    QTextStream out(&testFile);
    out << "test";
    testFile.close();

    // Set up the timer to close message boxes
    messageBoxTimer = new QTimer(this);
    connect(messageBoxTimer, &QTimer::timeout, this, &TestEncryptionApp::closeMessageBoxes);
    messageBoxTimer->start(500);  // Check every 500ms

    // Test encryption
    filePathInput->setText(QDir::currentPath() + "/test.txt");
    passwordInput->setText("testpassword");

    QTest::mouseClick(encryptButton, Qt::LeftButton);

    // Wait for encryption to complete and message box to appear
    QTRY_VERIFY_WITH_TIMEOUT(QFileInfo::exists(QDir::currentPath() + "/test.txt.enc"), 5000);

    // Verify that the encryption was successful
    QVERIFY(QFileInfo::exists(QDir::currentPath() + "/test.txt.enc"));

    // Test decryption
    filePathInput->setText(QDir::currentPath() + "/test.txt.enc");
    passwordInput->setText("testpassword");
    QTest::mouseClick(decryptButton, Qt::LeftButton);

    // Wait for decryption to complete and message box to appear
    QTRY_VERIFY_WITH_TIMEOUT(QFileInfo::exists(QDir::currentPath() + "/test.txt"), 5000);

    // Verify that the decryption was successful
    QVERIFY(QFileInfo::exists(QDir::currentPath() + "/test.txt"));

    // Verify content
    QFile file(QDir::currentPath() + "/test.txt");
    QVERIFY(file.open(QIODevice::ReadOnly | QIODevice::Text));
    QTextStream in(&file);
    QString content = in.readAll().trimmed();
    QCOMPARE(content, QString("test"));

    // Clean up
    QFile::remove(QDir::currentPath() + "/test.txt");
    QFile::remove(QDir::currentPath() + "/test.txt.enc");

    // Stop the timer
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
