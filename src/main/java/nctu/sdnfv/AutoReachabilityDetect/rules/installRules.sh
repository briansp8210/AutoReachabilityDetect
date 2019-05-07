#!/usr/bin/env bash

FILES=$(ls *ip*.json)

for f in $FILES; do
    curl -u onos:rocks -X POST -H "Content-Type: application/json" -d @$f http://localhost:8181/onos/v1/flows/of:0000000000000001
done
