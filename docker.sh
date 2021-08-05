#!/usr/bin/env bash

set -e

if ! [ -x "$(command -v docker)" ]; then
    echo docker is not installed 1>&2
    exit 1
fi

datadir=$(mktemp -d)

: "${img:=mysql/mysql-server:8.0.26}"
cname=mysql
mycnf=$(mktemp)
host=localhost
port=3406
user=root
password=dockword
if ! [[ "$OSTYPE" == "darwin"* ]]; then
    : # docker for mac does not support sharing unix sockets
    : # for details see: https://github.com/docker/for-mac/issues/483
    : # on linux it works, so you can uncomment it
else
    sock=${datadir}/mysql.sock
fi

echo +++ get default my.cnf
docker run --name $cname -d $img
docker cp $cname:/etc/my.cnf $mycnf
docker rm -f $cname

echo +++ docker run mysql container
env=(
    -e MYSQL_ROOT_PASSWORD=$password   # if not set, generates random onetime password
    -e MYSQL_ROOT_HOST=%               # allow root connections from other hosts
)
docker run \
    --name $cname \
    "${env[@]}" \
    -v $mycnf:/etc/my.cnf \
    -v $datadir:/var/lib/mysql \
    -p $port:3306 \
    -d $img


start_mysql() {
    docker start $cname
}

stop_mysql() {
    docker stop $cname
}

cleanup() {
    docker rm -f $cname
    rm -rf $mycnf
    rm -rf $datadir
}
