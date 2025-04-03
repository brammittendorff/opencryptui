#include "mainwindow.h"
#include <QApplication>
#include <openssl/crypto.h>
#include "version.h"
#include "logging/secure_logger.h"

int main(int argc, char *argv[])
{
    // Initialize OpenSSL with error checking
    if (!OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)) {
        // Using our secure logger instead of qCritical
        SecureLogger::getInstance().log(SecureLogger::LogLevel::ERROR_LEVEL, "MainApplication", "Failed to initialize OpenSSL");
        return EXIT_FAILURE;
    }
    
    // Configure logging
    SecureLogger& logger = SecureLogger::getInstance();
    
    // Check if running in CI environment
    if (isRunningInCI()) {
        // Disable all logging in CI/CD environment
        logger.setLogLevel(SecureLogger::LogLevel::ERROR_LEVEL);
        logger.setLogToFile(false);
    } else {
        #ifdef QT_DEBUG
            // More verbose logging in debug mode
            logger.setLogLevel(SecureLogger::LogLevel::DEBUG);
            logger.setLogToFile(true);
        #else
            // Limited logging in release mode
            logger.setLogLevel(SecureLogger::LogLevel::WARNING);
            logger.setLogToFile(false);
        #endif
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

    // Use SECURE_LOG instead of qDebug for logging MainWindow instances
    #ifdef QT_DEBUG
    SECURE_LOG(DEBUG, "MainApplication", 
        QString("Number of MainWindow instances: %1").arg(mainWindowCount));
    #endif

    // Show the MainWindow
    mainWindow.show();

    return app.exec();
}
