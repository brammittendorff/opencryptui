#!/bin/bash

# Run tests with suppressed Qt warnings
# This script is specifically designed for macOS compatibility
# It filters out Qt's internal debug logs while preserving test results

# Suppress all Qt internal categories
export QT_LOGGING_RULES="qt.*=false"

# Simplify output pattern
export QT_MESSAGE_PATTERN="[%{type}] %{message}"

# Run the tests and filter output
# Using a simpler grep command to avoid issues with macOS bash
./OpenCryptUITest "$@" 2>&1 | grep -v "QDEBUG" | grep -v "QFont" 