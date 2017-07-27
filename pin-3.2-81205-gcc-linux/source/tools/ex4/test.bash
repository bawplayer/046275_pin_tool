#! /bin/bash
rm rtn-output.txt
rm -r obj-intel64
make ex4.test
../../../pin -t obj-intel64/ex4.so -- ./bzip2 -k -f input.txt  >> rtn-output.txt 2>&1
less rtn-output.txt
