#!/bin/bash
#test.sh




filedatetime="$(date +%Y-%m-%d_%H-%M-%S)"

echo "$filedatetime" | tee -a /var/log/test.log | tee -a /tmp/test.log


