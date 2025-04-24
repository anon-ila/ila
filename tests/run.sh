#!/bin/bash

echo "$#"

if [ "$#" -ne 2 ]; then
   echo ""
   echo "Usage: $0 <backend> <scheme>"
   echo "       where"
   echo "            backend = { 1 (for seal), 2 (for openfhe), 3 (for tfhe-rs)}"
   echo "            scheme  = { 1 (for bgv),  2 (for bfv), 3 (for tfhe)}"
   echo ""
   exit 1
fi


backend=$1
scheme=$2

echo "Backend name: $backend"
echo "Scheme name : $scheme"

for i in type_infer/*.ila
do
    echo "\n++++++++++++++++++++++++++++\n"
    echo "Running" $i
    python3 ../ila.py $backend $scheme $i
    echo "\n++++++++++++++++++++++++++++\n"
done

