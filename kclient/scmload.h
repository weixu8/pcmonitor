#ifndef __SCMLOAD_H__
#define __SCMLOAD_H__

#pragma once

#include <Windows.h>


SC_HANDLE ScmOpenSCMHandle();

VOID ScmCloseSCMHandle(SC_HANDLE hscm);
// Функция установки драйвера на основе SCM вызовов
BOOL ScmInstallDriver( SC_HANDLE  scm, LPCTSTR DriverName, LPCTSTR driverExec );
// Функция удаления драйвера на основе SCM вызовов
BOOL ScmRemoveDriver(SC_HANDLE scm, LPCTSTR DriverName);
// Функция запуска драйвера на основе SCM вызовов
BOOL ScmStartDriver(SC_HANDLE  scm, LPCTSTR DriverName);
// Функция останова драйвера на основе SCM вызовов
BOOL ScmStopDriver(SC_HANDLE  scm, LPCTSTR DriverName);


#endif
