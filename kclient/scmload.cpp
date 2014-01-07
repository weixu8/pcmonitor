#include "scmload.h"
#include <stdio.h>

SC_HANDLE ScmOpenSCMHandle()
{
	SC_HANDLE hscm = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	
	if (hscm == NULL) {
		printf("Error OpenSCManager %d\n", GetLastError());
	}

	return hscm;
}

VOID ScmCloseSCMHandle(SC_HANDLE hscm)
{
	CloseServiceHandle(hscm);
}

// Функция установки драйвера на основе SCM вызовов
BOOL ScmInstallDriver( SC_HANDLE  scm, LPCTSTR DriverName, LPCTSTR driverExec )
{
	SC_HANDLE Service =
		CreateService ( scm,    // открытый дескриптор к SCManager
		DriverName,      // имя сервиса - Example
		DriverName,      // для вывода на экран
		SERVICE_ALL_ACCESS,    // желаемый доступ
		SERVICE_KERNEL_DRIVER, // тип сервиса
		SERVICE_DEMAND_START,  // тип запуска
		SERVICE_ERROR_NORMAL,  // как обрабатывается ошибка
		driverExec,            // путь к бинарному файлу
		// Остальные параметры не используются - укажем NULL
		NULL,    // Не определяем группу загрузки
		NULL, NULL, NULL, NULL);

	if (Service == NULL) // неудача
	{
		DWORD err = GetLastError();
		if (err == ERROR_SERVICE_EXISTS) {/* уже установлен */}
		// более серьезная ощибка:
		else  printf("Error can't create service %d\n", err);
		// (^^ Ётот код ошибки можно подставить в ErrLook):
		return FALSE;
	}
	CloseServiceHandle (Service);
	return TRUE;
}

// Функция удаления драйвера на основе SCM вызовов
BOOL ScmRemoveDriver(SC_HANDLE scm, LPCTSTR DriverName)
{
	SC_HANDLE Service =
		OpenService (scm, DriverName, SERVICE_ALL_ACCESS);
	if (Service == NULL) {
		printf("OpenService error %d\n", GetLastError());	
		return FALSE;
	}

	BOOL ret = DeleteService (Service);
	if (!ret) { /* неудача при удалении драйвера */ 
		printf("DeleteService error %d\n", GetLastError());
	}

	CloseServiceHandle (Service);
	return ret;
}

// Функция запуска драйвера на основе SCM вызовов
BOOL ScmStartDriver(SC_HANDLE  scm, LPCTSTR DriverName)
{
	SC_HANDLE Service = OpenService(scm, DriverName, SERVICE_ALL_ACCESS);
	
	if (Service == NULL) { 
		printf("OpenService error %d\n", GetLastError());	
		return FALSE; /* open failed */
	}

	BOOL ret =
		StartService( Service, // дескриптор
		0,       // число аргументов
		NULL  ); // указатель  на аргументы

	if (!ret) // неудача
	{
		DWORD err = GetLastError();
		if (err == ERROR_SERVICE_ALREADY_RUNNING)
			ret = TRUE; // OK, драйвер уже работает!
		else { /* другие проблемы */
			printf("StartService error %d\n", err);
		}
	}

	CloseServiceHandle (Service);
	return ret;
}

// Функция останова драйвера на основе SCM вызовов
BOOL ScmStopDriver(SC_HANDLE  scm, LPCTSTR DriverName)
{
	SC_HANDLE Service = OpenService (scm, DriverName, SERVICE_ALL_ACCESS );
	
	if (Service == NULL)  // Невозможно выполнить останов драйвера
	{
		DWORD err = GetLastError();
		printf("OpenService error %d\n", GetLastError());
		return FALSE;
	}

	SERVICE_STATUS serviceStatus;
	BOOL ret = ControlService(Service, SERVICE_CONTROL_STOP, &serviceStatus);
	if (!ret)
	{
		DWORD err = GetLastError();
		// дополнительная диагностика
		printf("ControlService error %d\n", GetLastError());
	}

	CloseServiceHandle (Service);
	return ret;
}

