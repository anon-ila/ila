#!/bin/bash

touch log.txt

for i in *.ila; do
	 echo  $i
	 python3 ../../../ila.py 2 $i > log.txt 
	 #python3 ../../../ila.py 1 $i > log.txt 
	 # extract all lines from log
	 val_ty=`grep -i "Type checker time in ms:" log.txt`
	 echo $val_ty
	 val_eval=`grep -i "Eval  time in ms:" log.txt`
	 echo $val_eval
done

