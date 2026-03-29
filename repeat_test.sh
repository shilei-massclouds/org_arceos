#!/bin/bash
#
# Usage: ./repeat_test.sh [TEST_NUM]
#
# Run app tests repeatedly. Will stop on first failure.
# Examples:
#   ./repeat_test.sh        # Run 1 time with default TEST_NUM=1
#   ./repeat_test.sh 10     # Run 10 times
#

TEST_NUM=${1:-1}

FAILED_COUNT=0

for ((i=0;i<$TEST_NUM;i++))
do
    echo "Running round $((i + 1))/$TEST_NUM..."
    make test 2>&1 | tee /tmp/test_output.log
    # Check if any test failed by looking for "failed!" in output
    if grep -q "failed!" /tmp/test_output.log; then
        echo "Test failed at round $((i + 1))"
        FAILED_COUNT=$((FAILED_COUNT + 1))
        break  # Stop on first failure
    fi
done

rm -f /tmp/test_output.log

if [ $FAILED_COUNT -gt 0 ]; then
    echo "$FAILED_COUNT test(s) failed out of $TEST_NUM"
    exit 1
else
    echo "All $TEST_NUM tests passed successfully!"
    exit 0
fi
