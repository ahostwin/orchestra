#!/bin/bash
#test.sh




filedatetime="$(date +%Y-%m-%d_%H-%M-%S)"

echo "$filedatetime" | tee -a /tmp/test.log | sudo tee -a /var/log/test.log


