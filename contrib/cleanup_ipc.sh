#!/bin/bash
for i in q m; do ipcs -$i | grep 0x | awk '{ print $2 }' | xargs -n 1 ipcrm -$i >/dev/null 2>&1; done; ipcs
