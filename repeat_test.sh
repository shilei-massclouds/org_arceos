#!/bin/bash
#
# Usage: ./repeat_test.sh [TEST_NUM]
#
# Run app tests repeatedly. Will stop on first failure.
# Examples:
#   ./repeat_test.sh        # Run 1 time with default TEST_NUM=1
#   ./repeat_test.sh 10     # Run 10 times
#

set -o pipefail

TEST_NUM=${1:-1}
LOG_FILE=/tmp/test_output.log
FAIL_PATTERN='failed!|timeout!'

FAILED_COUNT=0

cleanup() {
    rm -f "$LOG_FILE"
}

trap cleanup EXIT

for ((i=0;i<$TEST_NUM;i++))
do
    echo "Running round $((i + 1))/$TEST_NUM..."
    make test 2>&1 | tee "$LOG_FILE"
    test_status=$?

    # Stop immediately when the test log reports a failure or timeout.
    if grep -Eq "$FAIL_PATTERN" "$LOG_FILE"; then
        echo "Test failed or timed out at round $((i + 1))"
        FAILED_COUNT=$((FAILED_COUNT + 1))
        break  # Stop on first failure/timeout
    fi

    if [ $test_status -ne 0 ]; then
        echo "make test exited with status $test_status at round $((i + 1))"
        FAILED_COUNT=$((FAILED_COUNT + 1))
        break  # Stop on first failure
    fi
done

if [ $FAILED_COUNT -gt 0 ]; then
    echo "$FAILED_COUNT test(s) failed out of $TEST_NUM"
    exit 1
else
    echo "All $TEST_NUM tests passed successfully!"
    exit 0
fi
