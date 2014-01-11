#include "gdiplus.h"
#include <Gdiplus.h>

#if 0

#pragma comment(lib, "gdiplus.lib")

int GetEncoderClsid(const WCHAR* format, CLSID* pClsid)
{
	UINT  num = 0;          // number of image encoders
	UINT  size = 0;         // size of the image encoder array in bytes

	Gdiplus::ImageCodecInfo* pImageCodecInfo = NULL;

	Gdiplus::GetImageEncodersSize(&num, &size);
	if (size == 0)
		return -1;  // Failure

	pImageCodecInfo = (Gdiplus::ImageCodecInfo*)(malloc(size));
	if (pImageCodecInfo == NULL)
		return -1;  // Failure

	Gdiplus::GetImageEncoders(num, size, pImageCodecInfo);

	for (UINT j = 0; j < num; ++j)
	{
		if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0)
		{
			*pClsid = pImageCodecInfo[j].Clsid;
			free(pImageCodecInfo);
			return j;  // Success
		}
	}

	free(pImageCodecInfo);
	return -1;  // Failure
}


BOOL GdiPlusSaveBitmapAsPng(HBITMAP hBmp, WCHAR *FileName)
{
	BOOL Result = FALSE;
	CLSID   encoderClsid;
	Gdiplus::Status  status;
	Gdiplus::Bitmap* image = NULL;

	if (GetEncoderClsid(L"image/png", &encoderClsid) < 0) {
		goto done;
	}

	image = Gdiplus::Bitmap::FromHBITMAP(hBmp, NULL);
	if (image == NULL) {
		DebugPrint("Failure: Gdiplus::FromHBITMAP failed\n");
		goto done;
	}

	status = image->Save(FileName, &encoderClsid, NULL);
	if (status == Gdiplus::Ok) {
		Result = TRUE;
	} else {
		DebugPrint("Failure: Gdiplus::status = %d\n", status);
	}

done:
	if (image != NULL)
		delete image;

	return Result;
}

static 	ULONG_PTR gdiplusToken;

int GdiPlusStart()
{
	Gdiplus::Status  status;
	Gdiplus::GdiplusStartupInput gdiplusStartupInput;
	status = Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
	if (status != Gdiplus::Ok) {
		DebugPrint("GdiplusStartup failed\n");
	}

	return status;
}

void GdiPlusStop()
{
	Gdiplus::GdiplusShutdown(gdiplusToken);
}

#endif