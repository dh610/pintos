#!/bin/bash

cd build;

pintos -v -k -T 10 -m 20   --fs-disk=10 -p tests/filesys/base/syn-remove:syn-remove -- -q   -f run syn-remove > logfile.txt

tail -n +4 logfile.txt;

cd ..;
