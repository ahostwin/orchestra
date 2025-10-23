#!/bin/bash
#test.sh




filedatetime="$(date +%Y-%m-%d_%H-%M-%S)"

echo "$filedatetime" | tee -a /tmp/test.log

if [ "$EUID" -eq 0 ];  then
echo "$filedatetime" | sudo tee -a /var/log/test.log
fi

