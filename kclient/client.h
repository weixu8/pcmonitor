#pragma once

#include "..\kdriver\h\drvioctl.h"
#include <windows.h>

DWORD ClientDrvStart(char *clientId, char *authId);

DWORD ClientDrvStop(char *clientId, char *authId);

