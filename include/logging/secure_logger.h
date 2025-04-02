#ifndef SECURE_LOGGER_H
#define SECURE_LOGGER_H

#include <QString>
#include <QDebug>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QMutex>

class SecureLogger {
public:
    enum class LogLevel {
        DEBUG,
        INFO,
        WARNING,
        ERROR
    };

    // Singleton pattern
    static SecureLogger& getInstance();

    // Logging methods
    void log(LogLevel level, const QString& component, const QString& message);
    void setLogLevel(LogLevel level);
    void setLogToFile(bool enabled, const QString& filePath = QString());

    // Disable copy constructor and assignment operator
    SecureLogger(SecureLogger const&) = delete;
    void operator=(SecureLogger const&) = delete;

private:
    SecureLogger(); // Private constructor
    ~SecureLogger();

    LogLevel m_currentLogLevel;
    bool m_logToFile;
    QString m_logFilePath;
    QFile* m_logFile;
    QTextStream* m_logStream;
    QMutex m_mutex;

    // Convert log level to string
    QString logLevelToString(LogLevel level);

    // Sanitize log message (remove sensitive information)
    QString sanitizeMessage(const QString& message);
};

// Check for CI/CD environment
#ifndef SECURE_LOGGER_H_CI_ENV
#define SECURE_LOGGER_H_CI_ENV
#include <QProcessEnvironment>
inline bool isRunningInCI() {
    static bool checked = false;
    static bool inCI = false;
    if (!checked) {
        QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
        inCI = env.contains("CI") || env.contains("GITHUB_ACTIONS") || 
               env.contains("GITLAB_CI") || env.contains("TRAVIS");
        checked = true;
    }
    return inCI;
}
#endif

// Macro for logging with compile-time optimization
#if defined(QT_NO_DEBUG) || defined(QT_CI_BUILD)
    #define SECURE_LOG(level, component, message) do {} while (0)
#else
    #define SECURE_LOG(level, component, message) \
        if (!isRunningInCI()) { \
            SecureLogger::getInstance().log(SecureLogger::LogLevel::level, component, message); \
        }
#endif

#endif // SECURE_LOGGER_H