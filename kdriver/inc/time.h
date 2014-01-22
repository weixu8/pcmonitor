#pragma once
#include <inc/drvmain.h>

#define TIMEP_SYSTIME_CHARS 0x100

char *
TimepQuerySystemTime(PTIME_FIELDS pTimeFields);