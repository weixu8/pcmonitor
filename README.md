pcmonitor
=========

pcmonitor - windows kernel driver to monitor users activity(such as keyboard input, screenshot) and send encrypted reports to mobile applications in realtime through intermediate web server.

Project dirs -

\build - compiled binaries
\clients - different mobile clients
\injectstub - assembler stub for injection kdll.dll from kernel mode
\installer - installer
\jansson - code of jansson library used to make JSON. project link - http://www.digip.org/jansson/
\kclient - code of usermode kernel driver loader
\kdll - code of user-mode dll that makes screenshot inside windows sessions csrss.exe processes
\kdriver - kernel-mode driver code, that controls and monitors users and send report to server through TLSv1.2 channel based on Windows Kernel Sockers(WSK).
\keys - keys used for TLS between kdriver and server.
\logs - server logs directory
\polarssl2 - polarssl library adapted for usage in Windows kernel - mode. project link - https://polarssl.org/
\scripts - different deployment scripts

\server\cserver - server that handles incomming connections from client hosts. kdriver transfer data to cserver.
cserver stores data in files and Redis DB. cserver uses Java netty.io library for TLS (http://netty.io/)

\server\csite - web server with authorization&authentication based on Play Framework 2.2 ( http://www.playframework.com/ ) , jquery and bootstap

\server\shared - shared beetween csite and cserver java lib with set of usefull classes
\server\libs - different java jar used in project

kdriver.sln - VS2013 solution to build kdll, injectstub, kclient, kdriver, kdll projects.




