#!/usr/bin/env bash

set -e
if [ "$#" -ne 1 ]; then
    echo 'Usage: ./auth_test.sh SERVER_CTL_FILE' 1>&2
    echo 1>&2
    echo 'Examples:' 1>&2
    echo '     ./auth_test.sh ./homebrew.sh' 1>&2
    echo '     ./auth_test.sh ./docker.sh' 1>&2
    exit 1
fi
if ! [ -x "$(command -v mysql)" ]; then
    echo mysql client is not installed 1>&2
    exit 1
fi
source $1

plugins=(mysql_native sha256 caching_sha2)

tmp=$(mktemp -d)

mycnf_backup=$tmp/my.cnf
cp $mycnf $mycnf_backup

creds=$tmp/creds.cnf
cat > $creds << EOF
[client]
protocol = tcp
host = $host
port = $port
user = $user
password = $password
EOF

on_exit(){
    exit_code=$?

    echo +++ deleting users before exit
    if running; then
        for plugin in ${plugins[@]}; do
            execute "DROP USER IF EXISTS '${plugin}_user'@'%'"
        done
    fi
    set -ex
	cp $mycnf_backup $mycnf
    cleanup
    rm -rf cov.txt
	rm -rf $tmp

    if [ $exit_code -eq 0 ]; then
        echo 'script succeeded' >&2
    else
        echo "script failed at line $BASH_LINENO (exit code $exit_code)" >&2
    fi
}
trap on_exit EXIT

running() {
    mysql --defaults-extra-file=$creds --execute=exit > /dev/null 2>&1
}

start() {
    echo +++ starting mysql
    start_mysql
    while ! running; do
        echo mysql is not up yet
        sleep 3
    done
    echo mysql is up
}

stop() {
    echo +++ stopping mysql
    stop_mysql
    while running; do
        echo mystil is not down yet
        sleep 3
    done
    echo mysql is down
}

restart() {
    if running; then
        stop
    fi
    start
}

execute() {
    sql=$1
    echo +++ $sql
    mysql --defaults-extra-file=$creds --execute="$sql"
}

create_users() {
    for plugin in ${plugins[@]}; do
        pass=$(pwgen $plugin)
        execute "DROP USER IF EXISTS '${plugin}_user'@'%'"
        execute "CREATE USER '${plugin}_user'@'%' IDENTIFIED WITH ${plugin}_password BY '$pass'"
    done
}

run_tests() {
    for defplugin in ${plugins[@]}; do
        echo +++ set default_authentication_plugin=${defplugin}_password
        cp $mycnf_backup $mycnf
        echo default_authentication_plugin=${defplugin}_password >> $mycnf
        restart
        for plugin in ${plugins[@]}; do
            pass=$(pwgen $plugin)
            if [ -z "$sock" ]; then
                echo +++ skipped unix transport
            else
                echo +++ testing ${plugin} with default=$defplugin transport=unix
                go test -v -coverprofile cov.txt -mysql unix:$sock,user=${plugin}_user,password=$pass -run TestRemote_Authenticate
                cat cov.txt >> coverage.txt
            fi
            echo +++ testing ${plugin} with default=$defplugin transport=tcp
            go test -v -coverprofile cov.txt -mysql tcp:$host:$port,user=${plugin}_user,password=$pass -run TestRemote_Authenticate
            cat cov.txt >> coverage.txt
            echo +++ testing ${plugin} with default=$defplugin transport=ssl
            go test -v -coverprofile cov.txt -mysql tcp:$host:$port,user=${plugin}_user,password=$pass,ssl -run TestRemote_Authenticate
            cat cov.txt >> coverage.txt
        done
    done
}

rm -rf cov.txt coverage.txt

if ! running; then
    start
fi

echo '+++ testing with short password (less than 20 chars)'
pwgen() {
    plugin=$1
    echo -n ${plugin}_secret
}

create_users
run_tests

echo +++ testing with empty password

pwgen() {
    echo -n
}

create_users
run_tests

echo '+++ testing with long password (greater than 20 chars)'

pwgen() {
    plugin=$1
    echo -n ${plugin}_really_very_long_password
}

create_users
run_tests

echo '+++ run remaining tests'

restart
execute "CREATE DATABASE binlog"
go test -v -coverprofile cov.txt -mysql tcp:$host:$port,ssl,user=$user,password=$password,db=binlog
cat cov.txt >> coverage.txt
