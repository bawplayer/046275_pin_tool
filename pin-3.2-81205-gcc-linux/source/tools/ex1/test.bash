#! /bin/bash

make $1.test
../../../pin -t obj-intel64/$1.so -- ./bzip2 -k -f input.txt
diff recent_oren_rtn_output.txt rtn-output.txt
