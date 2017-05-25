#! /bin/bash
../../../pin -t obj-intel64/ex2.so -- ./bzip2 -k -f input.txt
less rtn-output.txt
