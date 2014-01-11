#pragma once

#include "project.h"
#include "debug.h"


int GdiPlusStart();
void GdiPlusStop();
BOOL GdiPlusSaveBitmapAsPng(HBITMAP hBmp, WCHAR *FileName);
