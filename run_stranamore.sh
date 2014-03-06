#!/bin/sh
#PBS -V
#PBS -N stranamore
#PBS -l nodes=120:ppn=4
#PBS -l walltime=10:00:00
#PBS -m bea
#PBS -M michele.orru Ⓐ studenti.unitn.it
cd /home/michele.orru/bachelor-master/

mpirun -hostfile $PBS_NODEFILE  ./src/stranamore modules

exit
