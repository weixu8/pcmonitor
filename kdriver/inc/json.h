#pragma once
#include <inc/drvmain.h>
#include <jansson/jansson.h>


typedef struct _JSON_MAP {
	json_t *object;
} JSON_MAP, *PJSON_MAP;

int JsonMapInit(PJSON_MAP map);
void JsonMapRelease(PJSON_MAP map);
int JsonMapSetString(PJSON_MAP map, const char *key, const char *value);
int JsonMapSetUlong(PJSON_MAP map, const char *key, ULONG value);
int JsonMapSetLong(PJSON_MAP map, const char *key, LONG value);
char *JsonMapDumps(PJSON_MAP map);


char *JsonMapGetString(PJSON_MAP map, const char *key);
int JsonMapGetUlong(PJSON_MAP map, const char *key, PULONG pvalue);
int JsonMapGetLong(PJSON_MAP map, const char *key, PLONG pvalue);

int JsonMapLoads(PJSON_MAP map, const char *json);

void JsonInit();

void * JsonAlloc(size_t size);

void JsonFree(void *ptr);