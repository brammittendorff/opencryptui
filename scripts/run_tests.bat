@echo off
:: Run tests with suppressed Qt warnings
:: This script completely filters out Qt's internal debug logs
:: while preserving the actual test results

:: Suppress all Qt internal categories 
set QT_LOGGING_RULES=qt.*=false

:: Simplify output pattern
set QT_MESSAGE_PATTERN=[%%{type}] %%{message}

:: Run the test with filtering
.\OpenCryptUITest.exe %*