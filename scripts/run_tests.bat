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

:: Create a temporary file for raw output
set TEMP_OUTPUT=%TEMP%\test_output.txt
if exist %TEMP_OUTPUT% del %TEMP_OUTPUT%

:: Run the test with output to temporary file
.\OpenCryptUITest.exe %* > %TEMP_OUTPUT% 2>&1

:: Read the temporary file and filter out Qt debug messages
type %TEMP_OUTPUT% | findstr /v "qt\." | findstr /v "QFont::"

:: Clean up
del %TEMP_OUTPUT%