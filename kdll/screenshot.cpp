#include "screenshot.h"
#include "debug.h"

BOOL CaptureAnImage()
{
	HDC hdcScreen = NULL;
	HDC hdcMemDC = NULL;
	HBITMAP hbmScreen = NULL;
	BITMAP bmpScreen;
	BOOL Result = FALSE;
	HGDIOBJ hOldObj = NULL;
	HWND hWnd = NULL;
	BOOL hOldObjValid = FALSE;
	HDESK hDesk = NULL;

	hWnd = GetDesktopWindow();
	if (hWnd == NULL) {
		DebugPrint("GetDesktopWindow failed\n");
		goto done;
	}
	// Retrieve the handle to a display device context for the client 
	// area of the window. 
	hdcScreen = GetDC(GetDesktopWindow());
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
	
	int cx = GetSystemMetrics(SM_CXSCREEN);
	int cy = GetSystemMetrics(SM_CYSCREEN);

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

	// Get the BITMAP from the HBITMAP
	GetObject(hbmScreen, sizeof(BITMAP), &bmpScreen);

	BITMAPFILEHEADER   bmfHeader;
	BITMAPINFOHEADER   bi;

	bi.biSize = sizeof(BITMAPINFOHEADER);
	bi.biWidth = bmpScreen.bmWidth;
	bi.biHeight = bmpScreen.bmHeight;
	bi.biPlanes = 1;
	bi.biBitCount = 32;
	bi.biCompression = BI_RGB;
	bi.biSizeImage = 0;
	bi.biXPelsPerMeter = 0;
	bi.biYPelsPerMeter = 0;
	bi.biClrUsed = 0;
	bi.biClrImportant = 0;

	DWORD dwBmpSize = ((bmpScreen.bmWidth * bi.biBitCount + 31) / 32) * 4 * bmpScreen.bmHeight;

	// Starting with 32-bit Windows, GlobalAlloc and LocalAlloc are implemented as wrapper functions that 
	// call HeapAlloc using a handle to the process's default heap. Therefore, GlobalAlloc and LocalAlloc 
	// have greater overhead than HeapAlloc.
	HANDLE hDIB = GlobalAlloc(GHND, dwBmpSize);
	char *lpbitmap = (char *)GlobalLock(hDIB);

	// Gets the "bits" from the bitmap and copies them into a buffer 
	// which is pointed to by lpbitmap.
	GetDIBits(hdcMemDC, hbmScreen, 0,
		(UINT)bmpScreen.bmHeight,
		lpbitmap,
		(BITMAPINFO *)&bi, DIB_RGB_COLORS);

	// A file is created, this is where we will save the screen capture.
	HANDLE hFile = CreateFile(L"\\\\?\\C:\\test\\screen.bmp",
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		DebugPrint("CreateFile failed\n");
		goto done;
	}

	// Add the size of the headers to the size of the bitmap to get the total file size
	DWORD dwSizeofDIB = dwBmpSize + sizeof(BITMAPFILEHEADER)+sizeof(BITMAPINFOHEADER);

	//Offset to where the actual bitmap bits start.
	bmfHeader.bfOffBits = (DWORD)sizeof(BITMAPFILEHEADER)+(DWORD)sizeof(BITMAPINFOHEADER);

	//Size of the file
	bmfHeader.bfSize = dwSizeofDIB;

	//bfType must always be BM for Bitmaps
	bmfHeader.bfType = 0x4D42; //BM   

	DWORD dwBytesWritten = 0;
	WriteFile(hFile, (LPSTR)&bmfHeader, sizeof(BITMAPFILEHEADER), &dwBytesWritten, NULL);
	WriteFile(hFile, (LPSTR)&bi, sizeof(BITMAPINFOHEADER), &dwBytesWritten, NULL);
	WriteFile(hFile, (LPSTR)lpbitmap, dwBmpSize, &dwBytesWritten, NULL);

	Result = TRUE;
done:
	//Close the handle for the file that was created
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);

	//Unlock and Free the DIB from the heap
	if (hDIB != NULL) {
		GlobalUnlock(hDIB);
		GlobalFree(hDIB);
	}
	
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

	if (hDesk != NULL)
		CloseDesktop(hDesk);

	return Result;
}