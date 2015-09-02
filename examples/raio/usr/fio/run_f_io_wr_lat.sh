#!/bin/bash


export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./.libs/:../../../src/usr/:../../../examples/raio/

taskset -c 1 $FIO_ROOT/fio ./raio_wr_lat.fio

wait

