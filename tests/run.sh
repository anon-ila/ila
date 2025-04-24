#!/bin/bash

echo "$#"

if [ "$#" -ne 2 ]; then
   echo ""
   echo "Usage: $0 <backend> <scheme>"
   echo "       where"
   echo "            backend = { seal, openfhe}"
   echo "            scheme  = { bgv, bfv, tfhe}"
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

