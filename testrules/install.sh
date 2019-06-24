#!/usr/bin/env bash

curl -u onos:rocks -X DELETE http://localhost:8181/onos/v1/flows/application/org.onosproject.rest

if [ $# -ne 0 ]; then
    FILES=$@
else
    FILES=$(ls *ip*.json)
fi

for f in $FILES; do
    curl -u onos:rocks -X POST -H "Content-Type: application/json" -d @$f http://localhost:8181/onos/v1/flows/of:0000000000000001
done
