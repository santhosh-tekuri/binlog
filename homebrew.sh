#!/usr/bin/env bash

mycnf=/opt/homebrew/etc/my.cnf
sock=/tmp/mysql.sock
host=127.0.0.1
port=3306
user=root
password=password

start_mysql() {
    brew services start mysql > /dev/null 2>&1
}

stop_mysql() {
    brew services stop mysql > /dev/null 2>&1
}

cleanup() {
    : no cleanup needed
}

