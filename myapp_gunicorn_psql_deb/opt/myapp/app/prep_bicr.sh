#!/bin/bash


cd /opt/myapp/app/bicry
pwd
gcc -shared -fPIC -o libbicry_openkey.so bicr_func.c -L. -lbicr5_64 -lbiogrn
cd ../../../../../
pwd
export LD_LIBRARY_PATH=/opt/myapp/app/bicry/:$LD_LIBRARY_PATH