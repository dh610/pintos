#!/bin/bash

cd build;

#pintos -v -k -T 600 -m 20 -m 20   --fs-disk=10 -p tests/userprog/no-vm/multi-oom:multi-oom -- -q   -f run multi-oom > logfile
pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/rox-child:rox-child -p tests/userprog/child-rox:child-rox -- -q   -f run rox-child > logfile

tail -n +4 logfile;

cd ..;
