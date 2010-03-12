#!/bin/sh
echo "Compiling $@ with debug maps"
./compile.sh $@ -- -clambc-map debug.map -clambc-dumpdi >debug.ll
echo "Map file is debug.map, IR dumped to debug.ll"
