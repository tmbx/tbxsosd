#!/bin/sh

if [ -z "$1" ]; then
    echo "Usage: deletekey.sh keyid"
    exit 1
fi

set -v -e

keyid=$1
S="sudo -u postgres"

$S psql -d pubkeys_db -c "delete from sig_key where key_id = $keyid;"
$S psql -d pubkeys_db -c "delete from enc_key where key_id = $keyid;"
$S psql -d pubkeys_db -c "delete from public_key where key_id = $keyid;"

$S psql -d privkeys_db -c "delete from sig_key where key_id = $keyid;"
$S psql -d privkeys_db -c "delete from enc_key where key_id = $keyid;"
$S psql -d privkeys_db -c "delete from private_key where key_id = $keyid;"
