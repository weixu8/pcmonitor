#include <Windows.h>
#include "scmload.h"
#include <stdio.h>
#include "..\kdriver\h\drvioctl.h"

#define KMON_BINARY_W (L".\\"KMON_DRIVER_NAME_W)

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

DWORD NTAPI CDrvInit(char *clientId, char *authId)
{
	HANDLE hDevice = NULL;
	DWORD BytesReturned;
	DWORD Result = -1;
	KMON_INIT InitData;

	hDevice = COpenDriver();
	if (hDevice == NULL) {
		return -1;
	}
	
	size_t authIdLen = strlen(authId) + 1;
	memcpy(&InitData.authId, authId, (authIdLen > sizeof(InitData.authId)) ? sizeof(InitData.authId) : authIdLen);

	size_t clientIddLen = strlen(clientId) + 1;
	memcpy(&InitData.clientId, clientId, (clientIddLen > sizeof(InitData.clientId)) ? sizeof(InitData.clientId) : clientIddLen);

	if( !DeviceIoControl(hDevice,
		IOCTL_KMON_INIT,
		&InitData, sizeof(InitData),	// Input
		&InitData, sizeof(InitData),	// Output
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

DWORD NTAPI CDrvRelease(char *clientId, char *authId)
{
	HANDLE hDevice = NULL;
	DWORD BytesReturned;
	DWORD Result = -1;
	KMON_RELEASE ReleaseData;

	hDevice = COpenDriver();
	if (hDevice == NULL) {
		return -1;
	}

	size_t authIdLen = strlen(authId) + 1;
	memcpy(&ReleaseData.authId, authId, (authIdLen > sizeof(ReleaseData.authId)) ? sizeof(ReleaseData.authId) : authIdLen);

	size_t clientIddLen = strlen(clientId) + 1;
	memcpy(&ReleaseData.clientId, clientId, (clientIddLen > sizeof(ReleaseData.clientId)) ? sizeof(ReleaseData.clientId) : clientIddLen);

	if( !DeviceIoControl(hDevice,
		IOCTL_KMON_RELEASE,
		&ReleaseData, sizeof(ReleaseData),
		&ReleaseData, sizeof(ReleaseData),
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

	err = GetFullPathName(KMON_BINARY_W, MAX_PATH, PathName, NULL);
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


DWORD ClientDrvStart(char *clientId, char *authId)
{
	if (CInstallDrv() == -1) {
		return -1;
	}
	
	if (CStartDrv() == -1) {
		return -1;
	}

	if (CDrvInit(clientId, authId) == -1) {
		return -1;
	}

	return 0;
}

DWORD ClientDrvStop(char *clientId, char *authId)
{
	CDrvRelease(clientId, authId);
	CStopDrv();
	CRemoveDrv();
	return 0;
}