#!/bin/sh
#PBS -V
#PBS -N stranamore
#PBS -l nodes=200:ppn=4
#PBS -l walltime=10:00:00
#PBS -m bea
#PBS -M michele.orru Ⓐ  studenti.unitn.it
cd /home/michele.orru/bachelor-master/

mpirun -loadbalance -hostfile $PBS_HOSTFILE ./src/stranamore modules
exit
