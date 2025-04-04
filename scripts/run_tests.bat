@echo off
:: Run tests with suppressed Qt warnings
:: This script completely filters out Qt's internal debug logs
:: while preserving the actual test results

:: Suppress all Qt internal categories 
set QT_LOGGING_RULES=qt.*=false

:: Set minimal QPA platform to avoid display issues
set QT_QPA_PLATFORM=minimal 

:: Simplify output pattern
set QT_MESSAGE_PATTERN=[%%{type}] %%{message}

:: Run the tests directly (no filtering for now)
OpenCryptUITest.exe %*