#!/bin/sh
# stacktest.sh
# run tests with decreasing stack until theyfail
set -e
set -u
#set -x

run_test() {
  sz=$1
  ulimit -s $STACK
  ./test.sh
}

PASS=50  # lowest KiB where tests pass
FAIL=1   # highest KiB where test fail

STACK=$FAIL

make

while [ $(($PASS-$FAIL)) -gt 1 ]; do
    echo "Testing at $STACK KiB, PASS=$PASS, FAIL=$FAIL"
    if run_test $STACK 2>/dev/null; then
        # test passed.  maybe bring PASS down
        test $STACK -lt $PASS && PASS=$STACK
    else
        # test failed. maybe bring FAIL up
        test $STACK -gt $FAIL && FAIL=$STACK
    fi

    STACK=$(( ($PASS+$FAIL) / 2 ))
done

echo "Stack usage; $PASS KiB"

exit 0
