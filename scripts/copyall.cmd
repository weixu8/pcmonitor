net use \\10.30.16.93 /user:guest 1q2w3eQAZ

xcopy "\\10.30.16.93\amd64\vzdsk.sys" "C:\Program Files\Parallels\Containers\Drivers\vzdsk.sys" /Y
xcopy "\\10.30.16.93\amd64\vzfs.sys" "C:\Program Files\Parallels\Containers\Drivers\vzfs.sys" /Y
xcopy "\\10.30.16.93\amd64\vzcore_w2k12r2.sys" "C:\Program Files\Parallels\Containers\Drivers\vzcore.sys" /Y
xcopy "\\10.30.16.93\amd64\vzktech_w2k12r2.sys" "C:\Program Files\Parallels\Containers\Drivers\vzktech.sys" /Y
xcopy "\\10.30.16.93\amd64\vzresdrv_win8.sys" "C:\Program Files\Parallels\Containers\Drivers\vzresdrv.sys" /Y
xcopy "\\10.30.16.93\amd64\vzsched_win8.sys" "C:\Program Files\Parallels\Containers\Drivers\vzsched.sys" /Y

xcopy "\\10.30.16.93\amd64\ksaldb.dat" "C:\Program Files\Parallels\Containers\Extras\ksaldb.dat" /Y
xcopy "\\10.30.16.93\amd64\on_vps_startup.cmd" "C:\Program Files\Parallels\Containers\BIN\on_vps_startup.cmd" /Y
xcopy "\\10.30.16.93\amd64\vzsrv_win8.exe" "C:\Program Files\Parallels\Containers\BIN\vzsrv.exe" /Y
xcopy "\\10.30.16.93\amd64\vzwinup.dll" "C:\Program Files\Parallels\Containers\BIN\vzwinup.dll" /Y
xcopy "\\10.30.16.93\amd64\vzscsi.sys" "C:\Program Files\Parallels\Containers\Drivers\vzscsi.sys" /Y
xcopy "\\10.30.16.93\amd64\vzdevport.sys" "C:\Program Files\Parallels\Containers\Drivers\vzdevport.sys" /Y
xcopy "\\10.30.16.93\amd64\vzpci.sys" "C:\Program Files\Parallels\Containers\Drivers\vzpci.sys" /Y
xcopy "\\10.30.16.93\amd64\vzwddm.sys" "C:\Program Files\Parallels\Containers\Drivers\vzwddm.sys" /Y
xcopy "\\10.30.16.93\amd64\vzblockflt.sys" "C:\Program Files\Parallels\Containers\Drivers\vzblockflt.sys" /Y
xcopy "\\10.30.16.93\amd64\vzscsimini.sys" "C:\Program Files\Parallels\Containers\Drivers\vzscsimini.sys" /Y
xcopy "\\10.30.16.93\amd64\vzvdd.sys" "C:\Program Files\Parallels\Containers\Drivers\vzvdd.sys" /Y
xcopy "\\10.30.16.93\amd64\vzreserve.sys" "C:\Program Files\Parallels\Containers\Drivers\vzreserve.sys" /Y
xcopy "\\10.30.16.93\amd64\vzlogon_win7.dll" "C:\Windows\System32\vzlogon.dll" /Y
xcopy "\\10.30.16.93\amd64\vzslsvc_win8.dll" "C:\Windows\System32\vzslsvc.dll" /Y
xcopy "\\10.30.16.93\amd64\vznet.dll" "C:\Windows\System32\vznet.dll" /Y

pause