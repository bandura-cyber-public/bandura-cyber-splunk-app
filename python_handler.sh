#!/bin/bash

if [[ $1 == stop ]]; then
    pkill -f filter_script.py
fi

if [[ $1 == start ]]; then
    nohup python3 /var/log/bandura/filter_script.py & >> /var/log/bandura/cron.out 1>&2
fi
