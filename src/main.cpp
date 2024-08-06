#include "mainwindow.h"
#include <QApplication>
#include <QDebug>
#include <openssl/crypto.h>

int main(int argc, char *argv[])
{
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    QApplication a(argc, argv);

    // Create an instance of MainWindow
    MainWindow w;

    // Check if there are any other instances of MainWindow
    QWidgetList topLevelWidgets = QApplication::topLevelWidgets();
    int mainWindowCount = 0;
    for (QWidget *widget : topLevelWidgets) {
        if (qobject_cast<MainWindow*>(widget)) {
            mainWindowCount++;
        }
    }

    // Print the number of MainWindow instances
    // Add this line to check if another instance of MainWindow is created
    static int mainWindowInstanceCount = 0;
    ++mainWindowInstanceCount;
    qDebug() << "Number of MainWindow instances:" << mainWindowCount;

    // Show the MainWindow
    w.show();

    return a.exec();
}