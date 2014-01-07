#ifndef __ECORE_H__
#define __ECORE_H__

#include <inc/drvmain.h>

NTSTATUS
    ECoreStart();

NTSTATUS
    ECoreStop();

VOID ECoreSendKbdBuf(PVOID BuffEntry);

#endif
