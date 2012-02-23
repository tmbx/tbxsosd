#!/bin/sh

set -e

#KCTLBIN=/home/fdgonthier/repos/tbxsosd/kctlbin
KCTLBIN=/usr/bin/kctlbin
DIR=/tmp/testkctlbin

[ -d $DIR ] && rm -rf $DIR
mkdir -p $DIR

# genkeys

$KCTLBIN genkeys sig 0 $DIR/testkey "Test KCTLBIN (blarg)"
if [ ! -s $DIR/testkey.sig.pkey -o ! -s $DIR/testkey.sig.skey ]; then
    echo "genkeys failed."
    exit 1
else
    echo "genkeys seems ok."
fi

# keysetname

$KCTLBIN keysetname $DIR/testkey.sig.pkey "Test KCTLBIN ok" $DIR/testkey.sig.pkey.nameok
$KCTLBIN keysetname $DIR/testkey.sig.skey "Test KCTLBIN ok" $DIR/testkey.sig.skey.nameok

grep -q ok $DIR/testkey.sig.pkey.nameok ok > /dev/null
RES_P=$?
grep -q ok $DIR/testkey.sig.skey.nameok ok > /dev/null
RES_S=$?

if [ $RES_S != 0 -o $RES_P != 0 -o ! -s $DIR/testkey.sig.pkey.nameok -o ! -s $DIR/testkey.sig.skey.nameok ]; then
    echo "keysetname failed."
    exit 1
else
    echo "keysetname seems ok."
fi

# keysetid

$KCTLBIN keysetid $DIR/testkey.sig.pkey.nameok 12 $DIR/testkey.sig.pkey.idok
$KCTLBIN keysetid $DIR/testkey.sig.skey.nameok 12 $DIR/testkey.sig.skey.idok

grep -q 12 $DIR/testkey.sig.pkey.idok > /dev/null
RES_P=$?
grep -q 12 $DIR/testkey.sig.skey.idok > /dev/null
RES_S=$?

if [ $RES_P != 0 -o $RES_S != 0 -o ! -s $DIR/testkey.sig.pkey.idok -o ! -s $DIR/testkey.sig.skey.idok ]; then
    echo "keysetid failed"
    exit 1
else
    echo "keysetid seems ok."
fi

# importkey

# printkey

# signlicense

# showlicense

# importlicense

echo "Done."