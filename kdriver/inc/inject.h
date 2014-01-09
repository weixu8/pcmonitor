
#pragma once

#include <inc/drvmain.h>

NTSTATUS
InjectFindAllProcessesAndInjectDll(PUNICODE_STRING ProcessPrefix, PUNICODE_STRING DllPath, PUNICODE_STRING DllName);

