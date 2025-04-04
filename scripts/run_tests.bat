@echo off
rem Run tests with proper environment variables set for Windows
rem This script runs the test executable with proper environment variables

rem Suppress Qt internal debug logging
set QT_LOGGING_RULES=qt.*=false

rem Set a simple message pattern
set QT_MESSAGE_PATTERN=[%%{type}] %%{message}

rem Run the tests
OpenCryptUITest.exe %*

rem Exit with the test's exit code
exit /b %ERRORLEVEL% 