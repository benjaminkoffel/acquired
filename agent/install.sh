#!/usr/bin/env bash
if [ "$1" = "" ]
then
    echo "Usage: $0 https://acquired.server.url"
    exit 1
fi
set -euxo pipefail
wget -O /usr/local/sbin/linpmem-2.1.post4 https://github.com/google/rekall/releases/download/v1.5.1/linpmem-2.1.post4
chmod 700 /usr/local/sbin/linpmem-2.1.post4
cp -f agent/acquired.py /usr/local/sbin
chmod 700 /usr/local/sbin/acquired.py
cp -f agent/acquired.service /etc/systemd/system
chmod 700 /etc/systemd/system/acquired.service
mkdir -p /usr/local/etc/acquired
mkdir -p /usr/local/etc/acquired/tasks
mkdir -p /usr/local/etc/acquired/artefacts
echo "$1" > /usr/local/etc/acquired/url
chmod 700 /usr/local/etc/acquired
service acquired restart
