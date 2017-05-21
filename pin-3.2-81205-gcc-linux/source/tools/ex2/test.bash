#! /bin/bash
make ex2.test
../../../pin -t obj-intel64/ex2.so -- ./bzip2 -k -f input.txt
less rtn-output.txt
