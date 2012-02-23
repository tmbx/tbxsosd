#!/bin/sh

KCTL=../kctl

echo "PLEASE NOTE THAT WE EXPECT AN EMPTY DB.  RUN DROPDB.SQL/MAIN.SQL."

$KCTL importkey source.enc.pkey
$KCTL importkey source.sig.skey
$KCTL importkey source.sig.pkey

$KCTL addorg "Source Organization" # Should be org 1
$KCTL addorg "Target Organization" # Should be org 2
$KCTL adduser 1 "Mister" "Source"
$KCTL adduser 2 "Miss" "Target"
$KCTL addpemail 1 source.com
$KCTL addpemail 2 target.com
$KCTL setkey 1 10
$KCTL setkey 2 11

