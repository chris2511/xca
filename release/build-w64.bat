REM Build xca on Windows

set BUILD=build

cmake -B %BUILD% -G "MinGW Makefiles" xca
cmake --build %BUILD% -j5
cd %BUILD%
cpack
