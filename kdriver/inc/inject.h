
#ifndef __MINJECT_H__
#define __MINJECT_H__

#include <inc/drvmain.h>

NTSTATUS
InjectFindAllProcessesAndInjectDll(PUNICODE_STRING ProcessPrefix, PUNICODE_STRING DllPath, PUNICODE_STRING DllName);

#endif
