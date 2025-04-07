#include "logging/secure_logger.h"
#include <QDir>
#include <QStandardPaths>

SecureLogger& SecureLogger::getInstance() {
    static SecureLogger instance;
    return instance;
}

SecureLogger::SecureLogger() 
    : m_currentLogLevel(LogLevel::WARNING),
      m_logToFile(false),
      m_logFile(nullptr),
      m_logStream(nullptr) {
    // Default log path in user's home directory
    m_logFilePath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/logs/opencryptui.log";
}

SecureLogger::~SecureLogger() {
    // Close and delete file if it exists
    if (m_logFile) {
        if (m_logFile->isOpen()) {
            m_logFile->close();
        }
        delete m_logFile;
    }
    
    // Delete stream if it exists
    if (m_logStream) {
        delete m_logStream;
    }
}

void SecureLogger::log(LogLevel level, const QString& component, const QString& message) {
    // All log control is now done in the SECURE_LOG macro
    QMutexLocker locker(&m_mutex);

    // Check if logging is allowed based on current log level
    if (level < m_currentLogLevel) return;

    // Sanitize the message
    QString sanitizedMessage = sanitizeMessage(message);

    // Prepare log entry
    QString logEntry = QString("[%1] [%2] %3: %4")
        .arg(QDateTime::currentDateTime().toString(Qt::ISODate))
        .arg(logLevelToString(level))
        .arg(component)
        .arg(sanitizedMessage);

    // Always log to console during tests
    bool isTest = qgetenv("QT_LOGGING_RULES").contains("*.debug=true") || 
                  component.startsWith("TestOpenCryptUI") || 
                  component.startsWith("Test");

    // Always log during debugging, but also always log for tests and OpenSSL provider
    // regardless of build type to help with debugging tests
    if (isTest || component.startsWith("OpenSSLProvider") || component == "EncryptionEngine") {
        switch(level) {
            case LogLevel::DEBUG:
                qDebug() << "SECLOG:" << logEntry;
                break;
            case LogLevel::INFO:
                qInfo() << "SECLOG:" << logEntry;
                break;
            case LogLevel::WARNING:
                qWarning() << "SECLOG:" << logEntry;
                break;
            case LogLevel::ERROR_LEVEL:
                qCritical() << "SECLOG:" << logEntry;
                break;
        }
    }
    #ifndef QT_NO_DEBUG
    else {
        switch(level) {
            case LogLevel::DEBUG:
                qDebug() << logEntry;
                break;
            case LogLevel::INFO:
                qInfo() << logEntry;
                break;
            case LogLevel::WARNING:
                qWarning() << logEntry;
                break;
            case LogLevel::ERROR_LEVEL:
                qCritical() << logEntry;
                break;
        }
    }
    #endif

    // File logging
    if (m_logToFile) {
        // Ensure log directory exists
        QDir().mkpath(QFileInfo(m_logFilePath).path());

        // Open log file
        if (!m_logFile) {
            m_logFile = new QFile(m_logFilePath);
            if (m_logFile->open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
                m_logStream = new QTextStream(m_logFile);
            }
        }

        // Write to file if possible
        if (m_logStream) {
            *m_logStream << logEntry << "\n";
            m_logStream->flush();
        }
    }
}

void SecureLogger::setLogLevel(LogLevel level) {
    m_currentLogLevel = level;
}

void SecureLogger::setLogToFile(bool enabled, const QString& filePath) {
    m_logToFile = enabled;
    if (!filePath.isEmpty()) {
        m_logFilePath = filePath;
    }
}

QString SecureLogger::logLevelToString(LogLevel level) {
    switch(level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR_LEVEL: return "ERROR";
        default: return "UNKNOWN";
    }
}

QString SecureLogger::sanitizeMessage(const QString& message) {
    // Implement basic sanitization
    QString sanitized = message;
    
    // Examples of sanitization:
    // 1. Remove potential sensitive paths
    sanitized.replace(QDir::homePath(), "[HOME]");
    
    // 2. Mask potential sensitive values (add more as needed)
    QStringList sensitiveKeywords = {"password", "key", "secret", "salt", "iv"};
    for (const auto& keyword : sensitiveKeywords) {
        int index = sanitized.indexOf(keyword, Qt::CaseInsensitive);
        if (index != -1) {
            sanitized.replace(index, keyword.length(), "[REDACTED]");
        }
    }

    return sanitized;
}
