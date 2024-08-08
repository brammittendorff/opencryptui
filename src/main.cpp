#include "mainwindow.h"
#include <QApplication>
#include <QDebug>
#include <openssl/crypto.h>
#include "version.h"

int main(int argc, char *argv[])
{
    // Initialize OpenSSL with error checking
    if (!OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)) {
        qCritical() << "Failed to initialize OpenSSL";
        return EXIT_FAILURE;
    }

    QApplication app(argc, argv);

    Q_INIT_RESOURCE(resources);

    // Create an instance of MainWindow
    MainWindow mainWindow;

    // Optionally, check if there are any other instances of MainWindow
    QWidgetList topLevelWidgets = QApplication::topLevelWidgets();
    int mainWindowCount = 0;
    for (QWidget *widget : topLevelWidgets) {
        if (qobject_cast<MainWindow*>(widget)) {
            mainWindowCount++;
        }
    }

    // Print the number of MainWindow instances
    qDebug() << "Number of MainWindow instances:" << mainWindowCount;

    // Show the MainWindow
    mainWindow.show();

    return app.exec();
}
