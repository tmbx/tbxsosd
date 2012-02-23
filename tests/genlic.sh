#!/bin/bash

set -e

KB=../kctlbin

function input {
    prompt=$1
    default=$2
    RET=

    echo -n $prompt
    read RET
    
    if [ -z "$RET" ]; then
        RET=$default
    fi
}

BEST_AFTER=`date +%Y-%m-%d`
BEST_BEFORE=$((`date +%Y` + 1))"-"`date +%m-%d`

input "KDN (teambox.test.source): " "teambox.test.source"
KDN=$RET

input "Parent KDN (none): " "none"
PARENT_KDN=$RET

input "Best after ($BEST_AFTER): " $BEST_AFTER
BEST_AFTER=$RET

input "Best before ($BEST_BEFORE): " $BEST_BEFORE
BEST_BEFORE=$RET

input "Seat limit (5): " "5"
SEAT_LIM=$RET

input "Seat maximum (10): " "10"
SEAT_MAX=$RET

input "Is Reseller (1): " "1"
IS_RESELLER=$RET

input "Capacities (sig enc pod apps): " "sig enc pod apps"
CAPACITIES=$RET

OUT=$KDN.lic

./kctlbin signlicense license_keys/license_test.sig.skey \
    $OUT $KDN $PARENT_KDN $BEST_BEFORE $BEST_AFTER $SEAT_LIM $SEAT_MAX $IS_RESELLER $CAPACITIES

echo "Saved license as $OUT."