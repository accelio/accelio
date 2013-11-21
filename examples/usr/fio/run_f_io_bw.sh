#!/bin/bash


export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./.libs/:../../../src/usr/:../../../examples/usr/raio/

taskset -c 6 $FIO_ROOT/fio ./raio-read-bw.fio

wait

