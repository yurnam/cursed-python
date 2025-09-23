#!/bin/bash

rm -rf dist build
x86_64-w64-mingw32-gcc -o chaos.exe chaos.c -static -static-libgcc -lpsapi -lshlwapi
x86_64-w64-mingw32-g++ -o frick.exe frick.cpp -lpsapi -pthread -static-libgcc -static-libstdc++

scp chaos.exe administrator@deploymaster-staging:/media/diskimages/drivers/
scp frick.exe administrator@deploymaster-staging:/media/diskimages/drivers/

wine pyinstaller --onefile wacc.py
scp dist/wacc.exe administrator@deploymaster-staging:/media/diskimages/drivers/

wine pyinstaller --onefile test.py
scp dist/test.exe administrator@deploymaster-staging:/media/diskimages/drivers/

wine pyinstaller dllfuz.spec
scp dist/dllfuz.exe administrator@deploymaster-staging:/media/diskimages/drivers/

