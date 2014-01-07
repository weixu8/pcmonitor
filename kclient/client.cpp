#include <Windows.h>
#include "scmload.h"
#include <stdio.h>
#include "..\kdriver\h\drvioctl.h"
#include "installation.h"

#define EYE_BINARY_W (EYE_INSTALLATION_DIR EYE_DRIVER_NAME_W)


DWORD NTAPI InstallDrv(int argc, char *argv[]);
DWORD NTAPI RemoveDrv(int argc, char *argv[]);
DWORD NTAPI StartDrv(int argc, char *argv[]);
DWORD NTAPI StopDrv(int argc, char *argv[]);
DWORD NTAPI DrvInit(int argc, char *argv[]);
DWORD NTAPI DrvRelease(int argc, char *argv[]);

HANDLE COpenDriver()
{

	HANDLE hDevice =           // Получаем доступ к драйверу
		CreateFile(KMON_WIN32_DEVICE_NAME_W,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL );

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("ERROR: can not access driver %ws, error %d\n", KMON_WIN32_DEVICE_NAME_W, GetLastError());
		return NULL;
	}

	return hDevice;
}

BOOL 
	CCloseDriver(
		IN HANDLE hDevice
		)
{
	return CloseHandle(hDevice);
}

DWORD NTAPI CDrvInit()
{
	HANDLE hDevice = NULL;
	DWORD BytesReturned;
	DWORD Result = -1;

	hDevice = COpenDriver();
	if (hDevice == NULL) {
		return -1;
	}
	
	if( !DeviceIoControl(hDevice,
		IOCTL_KMON_INIT,
		NULL, 0,	// Input
		NULL, 0,	// Output
		&BytesReturned,
		NULL )  )
	{
		printf( "Error in IOCTL_KMON_INIT %d\n", GetLastError());
		Result = -1;
	} else {
		Result = 0;
	}	


	CCloseDriver(hDevice);
	return Result;
}

DWORD NTAPI CDrvRelease()
{
	HANDLE hDevice = NULL;
	DWORD BytesReturned;
	DWORD Result = -1;

	hDevice = COpenDriver();
	if (hDevice == NULL) {
		return -1;
	}

	if( !DeviceIoControl(hDevice,
		IOCTL_KMON_RELEASE,
		NULL, 0,	// Input
		NULL, 0,	// Output
		&BytesReturned,
		NULL )  )
	{
		printf( "Error in IOCTL_CPP_RELEASE %d", GetLastError());
		Result = -1;
	} else {
		Result = 0;
	}	

	CCloseDriver(hDevice);
	return Result;
}

DWORD NTAPI CInstallDrv()
{
	SC_HANDLE hscm = NULL;
	DWORD err;
	WCHAR PathName[MAX_PATH];

	err = GetFullPathName(KMON_INSTALLATION_DIR_W, MAX_PATH, PathName, NULL);
	if (err == 0) {
		printf("GetFullPathName error\n");
		return -1;
	}

	hscm = ScmOpenSCMHandle();
	if (hscm == INVALID_HANDLE_VALUE) {
		printf("Error OpenSCMHandle\n");
		return -1;
	}
	
	
	printf("drv binary %ws\n", PathName);
	if (!ScmInstallDriver(hscm, KMOM_NAME_W, PathName)) {
		err = GetLastError();
		if (err == ERROR_SERVICE_EXISTS) {
			goto cleanup;
		}
		printf("Error install driver err %x\n", err);
		return -1;
	}

cleanup:
	if (hscm != NULL) {
		ScmCloseSCMHandle(hscm);
	}

	return 0;
}

DWORD NTAPI CRemoveDrv()
{
	SC_HANDLE hscm = NULL;
	hscm = ScmOpenSCMHandle();
	if (hscm == INVALID_HANDLE_VALUE) {
		printf("Error OpenSCMHandle\n");
		return -1;
	}

	if (!ScmRemoveDriver(hscm, KMOM_NAME_W)) {
		printf("Error remove driver\n");
		return -1;
	}

	if (hscm != NULL) {
		ScmCloseSCMHandle(hscm);
	}
	return 0;
}

DWORD NTAPI CStartDrv()
{
	SC_HANDLE hscm = NULL;
	hscm = ScmOpenSCMHandle();
	if (hscm == INVALID_HANDLE_VALUE) {
		printf("Error OpenSCMHandle\n");
		return -1;
	}

	if (!ScmStartDriver(hscm, KMOM_NAME_W)) {
		printf("Error start driver\n");
		return -1;
	}

	if (hscm != NULL) {
		ScmCloseSCMHandle(hscm);
	}
	return 0;
}

DWORD NTAPI CStopDrv()
{
	SC_HANDLE hscm = NULL;
	hscm = ScmOpenSCMHandle();
	if (hscm == INVALID_HANDLE_VALUE) {
		printf("Error OpenSCMHandle\n");
		return -1;
	}

	if (!ScmStopDriver(hscm, KMOM_NAME_W)) {
		printf("Error stop driver\n");
		return -1;
	}

	if (hscm != NULL) {
		ScmCloseSCMHandle(hscm);
	}

	return 0;
}


DWORD ClientDrvStart()
{
	if (CInstallDrv() == -1) {
		return -1;
	}
	
	if (CStartDrv() == -1) {
		return -1;
	}

	if (CDrvInit() == -1) {
		return -1;
	}

	return 0;
}

DWORD ClientDrvStop()
{
	CDrvRelease();
	CStopDrv();
	CRemoveDrv();
	return 0;
}