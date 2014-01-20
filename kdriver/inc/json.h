#pragma once
#include <inc/drvmain.h>
#include <jansson/jansson.h>


typedef struct _JSON_MAP {
	json_t *object;
} JSON_MAP, *PJSON_MAP;

void JsonMapInit(PJSON_MAP map);
void JsonMapRelease(PJSON_MAP map);
int JsonMapSetString(PJSON_MAP map, const char *key, const char *value);
int JsonMapSetUlong(PJSON_MAP map, const char *key, ULONG value);
int JsonMapSetLong(PJSON_MAP map, const char *key, LONG value);
char *JsonMapDumps(PJSON_MAP map);

void JsonInit();

void * JsonAlloc(size_t size);

void JsonFree(void *ptr);