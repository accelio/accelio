#!/bin/bash


export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./.libs/:../../../src/usr/:../../../examples/usr/raio/

taskset -c 1 $FIO_ROOT/fio ./raio_wr_bw.fio

wait

