#!/bin/bash

# Run tests with suppressed Qt warnings
# This script completely filters out Qt's internal debug logs
# while preserving the actual test results

# Suppress all Qt internal categories
export QT_LOGGING_RULES="qt.*=false"

# Simplify output pattern
export QT_MESSAGE_PATTERN="[%{type}] %{message}"

# Run the tests and filter output
./OpenCryptUITest "$@" 2>&1 | grep -v "^QDEBUG : TestOpenCryptUI::initTestCase() \[debug\] qt\." | grep -v "^QDEBUG : TestOpenCryptUI::initTestCase() \[debug\] QFont::"