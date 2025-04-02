#!/bin/bash
# CI Test Runner - Runs tests with minimal log output
# Used in CI/CD environments to reduce log noise

# Set CI environment variables
export CI=true
export QT_LOGGING_RULES="*.debug=false;*.info=false;*.warning=false"
export QT_MESSAGE_PATTERN=""

# Run the tests with minimal output
cd "$(dirname "$0")/build"
./OpenCryptUITest -silent -v1

# Exit with the same exit code as the test run
exit $?