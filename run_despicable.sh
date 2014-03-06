#!/bin/sh
#PBS -V
#PBS -N despicable
#PBS -l nodes=120:ppn=4
#PBS -l walltime=8:00:00
#PBS -m bea
#PBS -M michele.orru Ⓐ  studenti.unitn.it
cd /home/michele.orru/bachelor-master/

mpirun -hostfile $PBS_NODEFILE  ./src/despicable ukeys.ne.csv

exit
