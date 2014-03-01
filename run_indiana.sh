#!/bin/sh
#PBS -V
#PBS -N indiana
#PBS -l nodes=20
#PBS -l walltime=10:00:00
#PBS -m bea
#PBS -M michele.orru Ⓐ studenti.unitn.it
cd /home/michele.orru/bachelor-master/

unset http_proxy
unset https_proxy
mpirun -n 400 ./src/indiana
exit
