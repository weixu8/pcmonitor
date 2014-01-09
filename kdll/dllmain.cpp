// dllmain.cpp : Defines the entry point for the DLL application.
#include "project.h"
#include "monitor.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	BOOL Result = FALSE;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		Result = MonitorStart();
		break;
	case DLL_THREAD_ATTACH:
		Result = TRUE;
		break;
	case DLL_THREAD_DETACH:
		Result = TRUE;
		break;
	case DLL_PROCESS_DETACH:
		MonitorStop();
		Result = TRUE;
		break;
	}

	return Result;
}

