#include <QtTest>
#include "test_encryption_app.h"

int main(int argc, char *argv[])
{
    // Create the application
    QApplication app(argc, argv);
    
    // Set the logging level to DEBUG for tests
    SecureLogger::getInstance().setLogLevel(SecureLogger::LogLevel::DEBUG);
    
    // Create the test object
    TestOpenCryptUI testObj;
    
    // Run the tests
    if (argc > 1) {
        // If a test name is provided, run only that test
        QString testName = argv[1];
        qDebug() << "Running specific test:" << testName;
        return QTest::qExec(&testObj, QStringList() << argv[0] << testName);
    } else {
        // Run all tests
        return QTest::qExec(&testObj, argc, argv);
    }
} 