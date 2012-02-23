#!/bin/bash

cluster_port=
if [ ! -z "$2" ]; then
    # Target this specific cluster.
    port=$(pg_lsclusters -h | grep $1 | awk '{print $3}')
    if [ -z "$port" ]; then
        echo "Cannot find port for cluster $2."
        kctl_port="--db_port="$port
        psql_port="-p "$port
    fi
fi

KCTL=../kctl/main.py
DB=
# FIXME: Make this use KCTL eventually.
case $1 in
    single)
        DB=tbxsosd_db
        ;;
    multi)
        DB=profiles_db
        ;;
    *)
        echo "tests/test_setup.sh multi|single"
        exit 1
esac

KCTL="python /home/fdgonthier/repos/kctl/main.py $kctl_port --debug"

for i in tests/*key; do
    $KCTL importkey $i
done

(cd .. && $KCTL addorg "teambox.test.source") # Should be org 1
(cd .. && $KCTL addorg "teambox.test.target") # Should be org 2
(cd .. && $KCTL adduser 1 "Mister" "Source")
(cd .. && $KCTL adduser 2 "Miss" "Target")
(cd .. && $KCTL addpemail 1 source@source.com)
(cd .. && $KCTL addpemail 2 target@target.com)
(cd .. && $KCTL addlogin 1 1 source source)
(cd .. && $KCTL addlogin 2 2 target target)
(cd .. && $KCTL setkey 1 10)
(cd .. && $KCTL setkey 2 11)

# FIXME: Make this use KCTL eventually.
sudo psql $psql_port -d $DB -c \
    "select add_group_profile(1, 'Mister Source Group')";
sudo psql $psql_port -d $DB -c \
    "select add_group_profile(2, 'Miss Target Group')";
sudo psql $psql_port -d $DB -c \
    "select add_ldap_group(1, 'CN=Mister Source Group,OU=KPS,DC=ad,DC=local')"
sudo psql $psql_port -d $DB -c \
    "select add_ldap_group(2, 'CN=Miss Target Group,OU=KPS,DC=ad,DC=local')"
sudo psql $psql_port -d $DB -c \
    "select set_key(3, 10);"
sudo psql $psql_port -d $DB -c \
    "select set_key(4, 11);"

