#ifndef __DRVMAIN_H__
#define __DRVMAIN_H__
#pragma once

#ifdef __cplusplus
extern "C" {
#endif


#include <ntifs.h>
#include <wsk.h>
#ifdef __cplusplus
}
#endif

#ifdef DBG
#define DPRINT DbgPrint
#else
#define DPRINT
#endif


#define DO_DEBUG __asm int 3

#include "basictypes.h"

#endif
