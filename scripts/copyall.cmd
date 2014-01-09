net use \\10.30.16.93 /user:guest 1q2w3eQAZ

xcopy "\\10.30.16.93\build\x64\Release\kclient.exe" "C:\test\kclient.exe" /Y
xcopy "\\10.30.16.93\build\x64\Release\kdll.dll" "C:\test\kdll.dll" /Y
xcopy "\\10.30.16.93\build\x64\Win7 Debug\kdriver.sys" "C:\test\kdriver.sys" /Y

pause