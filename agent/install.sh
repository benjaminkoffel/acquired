#!/usr/bin/env bash
wget -O /usr/bin/local/ https://github.com/google/rekall/releases/download/v1.5.1/linpmem-2.1.post4
chmod 700 /usr/bin/local/linpmem-2.1.post4
cp -f acquired.py /usr/bin/local/
chmod 700 /usr/bin/local/acquired.py
cp -f acquired.service /etc/systemd/system/
chmod 700 /etc/systemd/system/acquired.service
