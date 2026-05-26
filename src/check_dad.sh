#!/bin/bash

# Usage: ./check_dad.sh <interface>

INTERFACE=$1

if [ -z "$INTERFACE" ]; then
    echo "Usage: $0 <interface>"
    exit 1
fi

# Give the kernel time to complete asynchronous Duplicate Address Detection.
for _ in $(seq 1 30); do
    if ip a show dev "$INTERFACE" | grep -q "dadfailed"; then
        echo "DAD failed on interface $INTERFACE"
        exit 2
    fi

    if ! ip a show dev "$INTERFACE" | grep -q "tentative"; then
        exit 0
    fi

    sleep 0.1
done

exit 0
