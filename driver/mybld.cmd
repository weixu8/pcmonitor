@echo off
set DDK_PATH=C:\WinDDK\7600.16385.1
set SRC_PATH=.
set TARGET=WIN7
set ARCH=x64
set BUILD_OPTIONS=-I
set BUILD=fre

cd %SRC_PATH%
pushd .
call %DDK_PATH%\bin\setenv.bat %DDK_PATH% %BUILD% %ARCH% %TARGET%
popd

build %BUILD_OPTIONS%

echo obj%BUILD%_%TARGET%_amd64
rmdir /S /Q obj%BUILD%_%TARGET%_amd64

del /Q *.log

call postbuild.cmd
pause