#include "screenshot.h"
#include "debug.h"
#include <stdio.h>

typedef struct _BITMAP_DATA {
	BITMAP bmp;
	BITMAPINFOHEADER bmInfoHeader;
	BITMAPFILEHEADER bmFileHeader;
	char *bits;
	DWORD bitsSize;
} BITMAP_DATA, *PBITMAP_DATA;

VOID
	BitmapDataInit(PBITMAP_DATA bmData)
{
	memset(bmData, 0, sizeof(BITMAP_DATA));
}

VOID
	BitmapDataRelease(PBITMAP_DATA bmData)
{
	if (bmData->bits != NULL)
		HeapFree(GetProcessHeap(), 0, bmData->bits);
	memset(bmData, 0, sizeof(BITMAP_DATA));
}

BOOL BitmapDataSet(HDC hdcMemDC, HBITMAP hbmScreen, PBITMAP_DATA bmData)
{
	BOOL Result = FALSE;

	if (0 == GetObject(hbmScreen, sizeof(BITMAP), &bmData->bmp)) {
		DebugPrint("cant get bitmap from hbm");
		goto done;
	}

	bmData->bmInfoHeader.biSize = sizeof(BITMAPINFOHEADER);
	bmData->bmInfoHeader.biWidth = bmData->bmp.bmWidth;
	bmData->bmInfoHeader.biHeight = bmData->bmp.bmHeight;
	bmData->bmInfoHeader.biPlanes = 1;
	bmData->bmInfoHeader.biBitCount = 32;
	bmData->bmInfoHeader.biCompression = BI_RGB;
	bmData->bmInfoHeader.biSizeImage = 0;
	bmData->bmInfoHeader.biXPelsPerMeter = 0;
	bmData->bmInfoHeader.biYPelsPerMeter = 0;
	bmData->bmInfoHeader.biClrUsed = 0;
	bmData->bmInfoHeader.biClrImportant = 0;

	bmData->bitsSize = ((bmData->bmp.bmWidth * bmData->bmInfoHeader.biBitCount + 31) / 32) * 4 * bmData->bmp.bmHeight;

	bmData->bits = (char *)HeapAlloc(GetProcessHeap(), 0, bmData->bitsSize);
	if (bmData->bits == NULL) {
		DebugPrint("failed to alloc %x bytes\n", bmData->bitsSize);
		goto done;
	}

	DWORD dwError;
	// Gets the "bits" from the bitmap and copies them into a buffer 
	// which is pointed to by lpbitmap.
	dwError = GetDIBits(hdcMemDC, hbmScreen, 0,
		(UINT)bmData->bmp.bmHeight,
		bmData->bits,
		(BITMAPINFO *)&bmData->bmInfoHeader, DIB_RGB_COLORS);
	if (dwError == ERROR_INVALID_PARAMETER) {
		DebugPrint("GetDIBits error=%x\n", dwError);
		goto done;
	}

	if (dwError == 0) {
		DebugPrint("GetDIBits error=%x\n", dwError);
		goto done;
	}

	// Add the size of the headers to the size of the bitmap to get the total file size
	DWORD dwSizeofDIB = bmData->bitsSize + sizeof(BITMAPFILEHEADER)+sizeof(BITMAPINFOHEADER);

	//Offset to where the actual bitmap bits start.
	bmData->bmFileHeader.bfOffBits = (DWORD)sizeof(BITMAPFILEHEADER)+(DWORD)sizeof(BITMAPINFOHEADER);

	//Size of the file
	bmData->bmFileHeader.bfSize = dwSizeofDIB;

	//bfType must always be BM for Bitmaps
	bmData->bmFileHeader.bfType = 0x4D42; //BM  
	Result = TRUE;

done:
	if (!Result) {
		BitmapDataRelease(bmData);
	}

	return Result;
}

DWORD 
	BitmapDataSaveToFile(WCHAR *FileName, PBITMAP_DATA bmData)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD error = ERROR_ACCESS_DENIED;

	DWORD dwBytesWritten = 0;

	hFile = CreateFile(FileName,
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		DebugPrint("CreateFile failed\n");
		error = GetLastError();
		goto done;
	}

	if (!WriteFile(hFile, (LPSTR)&bmData->bmFileHeader, sizeof(BITMAPFILEHEADER), &dwBytesWritten, NULL)) {
		DebugPrint("Failed to write into file");
		goto done;
	}

	if (sizeof(BITMAPFILEHEADER) != dwBytesWritten) {
		DebugPrint("Failed to write into file");
		goto done;
	}

	if (!WriteFile(hFile, (LPSTR)&bmData->bmInfoHeader, sizeof(BITMAPINFOHEADER), &dwBytesWritten, NULL)) {
		DebugPrint("Failed to write into file");
		goto done;
	}

	if (sizeof(BITMAPINFOHEADER) != dwBytesWritten) {
		DebugPrint("Failed to write into file");
		goto done;
	}

	if (!WriteFile(hFile, (LPSTR)bmData->bits, bmData->bitsSize, &dwBytesWritten, NULL)) {
		DebugPrint("Failed to write into file");
		goto done;
	}

	if (bmData->bitsSize != dwBytesWritten) {
		DebugPrint("Failed to write into file");
		goto done;
	}

	error = ERROR_SUCCESS;

done:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);

	if ((error != ERROR_SUCCESS) && (hFile != INVALID_HANDLE_VALUE)) {
		DeleteFile(FileName);
	}

	return error;
}

BOOL CaptureAnImage(HWND hWnd, PBITMAP_DATA bmData)
{
	HDC hdcScreen = NULL;
	HDC hdcMemDC = NULL;
	HBITMAP hbmScreen = NULL;
	HGDIOBJ hOldObj = NULL;
	BOOL hOldObjValid = FALSE;
	BOOL Result = FALSE;
	RECT wRect;

	DebugPrint("CaptureAnImage wnd=%x\n", hWnd);

	if (!GetWindowRect(hWnd, &wRect)) {
		DebugPrint("GetWindowRect() failed, error=%d\n", GetLastError());
		goto done;
	}
	
	// Retrieve the handle to a display device context for the client 
	// area of the window. 
	hdcScreen = GetDC(hWnd);
	if (hdcScreen == NULL) {
		DebugPrint("GetDC() failed\n");
		goto done;
	}

	// Create a compatible DC which is used in a BitBlt from the window DC
	hdcMemDC = CreateCompatibleDC(hdcScreen);
	if (!hdcMemDC)
	{
		DebugPrint("CreateCompatibleDC failed\n");
		goto done;
	}
	
	int cx = wRect.right - wRect.left;
	int cy = wRect.bottom - wRect.top;

	// Create a compatible bitmap from the Window DC
	hbmScreen = CreateCompatibleBitmap(hdcScreen, cx, cy);

	if (!hbmScreen)
	{
		DebugPrint("CreateCompatibleBitmap failed\n");
		goto done;
	}

	// Select the compatible bitmap into the compatible memory DC.
	hOldObj = SelectObject(hdcMemDC, hbmScreen);
	hOldObjValid = TRUE;

	// Bit block transfer into our compatible memory DC.
	if (!BitBlt(hdcMemDC,
		0, 0,
		cx, cy,
		hdcScreen,
		0, 0,
		SRCCOPY))
	{
		DebugPrint("BitBlt failed\n");
		goto done;
	}

	if (!BitmapDataSet(hdcMemDC, hbmScreen, bmData)) {
		DebugPrint("BitmapDataSet failed\n");
		goto done;
	}
	
	Result = TRUE;
done:

	//Clean up
	if (hbmScreen != NULL)
		DeleteObject(hbmScreen);
	
	if (hdcMemDC != NULL) {
		if (hOldObjValid)
			SelectObject(hdcMemDC, hOldObj);
		DeleteObject(hdcMemDC);
	}

	if (hdcScreen != NULL)
		ReleaseDC(hWnd, hdcScreen);

	return Result;
}

VOID
	DoScreenShot(HWND hWnd, WCHAR *FileNamePrefix)
{
	BITMAP_DATA bmData;
	if (hWnd == NULL) {
		DebugPrint("hWnd = NULL\n");
		return;
	}

	BitmapDataInit(&bmData);
	if (!CaptureAnImage(hWnd, &bmData)) {
		DebugPrint("CaptureAnImage failed\n");
		goto done;
	}

	WCHAR FileName[0x100];
	DWORD sessionId = -1;
	DWORD pid = GetCurrentProcessId();
	if (!ProcessIdToSessionId(pid, &sessionId)) {
		DebugPrint("ProcessIdToSessionId failed err=%d\n", GetLastError());
	}

	SYSTEMTIME st;
	GetSystemTime(&st);

	_snwprintf_s((WCHAR *)FileName, sizeof(FileName), _TRUNCATE, L"%ws\\%ws_s%u_t%02d_%02d_%02d.bmp", L"\\\\?\\C:\\test", FileNamePrefix, sessionId,
		st.wHour, st.wMinute, st.wSecond);

	BitmapDataSaveToFile(FileName, &bmData);
done:
	BitmapDataRelease(&bmData);
}

VOID
	CaptureScreenCallback()
{
	HWND hWndDesk = GetDesktopWindow();
	if (hWndDesk != NULL)
		DoScreenShot(hWndDesk, L"desktop");

	HWND hWndForeground = GetForegroundWindow();
	if (hWndForeground != NULL)
		DoScreenShot(hWndForeground, L"foreground");
}

