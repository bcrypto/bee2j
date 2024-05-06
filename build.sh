#!/bin/sh

# Build bee2 for Linux
mkdir build
cd build
cmake ..
make
cd ..

# Build bee2 for Windows
mkdir build_win
cd build_win
cmake -DCMAKE_TOOLCHAIN_FILE="../mingw.cmake" ..
make
cd ..

cp build/bee2/src/libbee2.so src/main/resources/libbee2.so
cp build_win/bee2/src/libbee2.dll src/main/resources/bee2.dll

mvn clean install