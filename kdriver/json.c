#include <inc/json.h>
#include <inc/klogger.h>

#define __SUBCOMPONENT__ "json"
#define MODULE_TAG 'jsal'

void * JsonAlloc(size_t size)
{
	return ExAllocatePoolWithTag(NonPagedPool, size, MODULE_TAG);
}

void JsonFree(void *ptr)
{
	ExFreePoolWithTag(ptr, MODULE_TAG);
}

void JsonMapInit(PJSON_MAP map)
{
	RtlZeroMemory(map, sizeof(JSON_MAP));
	map->object = json_object();
}

void JsonMapRelease(PJSON_MAP map)
{
	if (map->object != NULL)
		json_decref(map->object);
}

int JsonMapSetString(PJSON_MAP map, const char *key, const char *value)
{
	json_t *value_t = json_string(value);
	int res = -1;

	if (value_t == NULL) {
		KLog(LError, "json_string failed for value %s\n", value);
		return -1;
	}

	res = json_object_set(map->object, key, value_t);
	if (value_t != NULL)
		json_decref(value_t);

	return res;
}

int JsonMapSetUlong(PJSON_MAP map, const char *key, ULONG value)
{
	json_t *value_t = json_integer(value);
	int res = -1;

	if (value_t == NULL) {
		KLog(LError, "json_string failed for value %u\n", value);
		return -1;
	}

	res = json_object_set(map->object, key, value_t);
	if (value_t != NULL) {
		json_decref(value_t);
	}

	return res;
}

int JsonMapSetLong(PJSON_MAP map, const char *key, LONG value)
{
	json_t *value_t = json_integer(value);
	int res = -1;

	if (value_t == NULL) {
		KLog(LError, "json_string failed for value %d\n", value);
		return -1;
	}

	res = json_object_set(map->object, key, value_t);
	if (value_t != NULL)
		json_decref(value_t);

	return res;
}

char *JsonMapDumps(PJSON_MAP map)
{
	return json_dumps(map->object, 0);
}

void JsonSelfTest()
{
	JSON_MAP map;
	char *encoded = NULL;

	JsonMapInit(&map);

	if (JsonMapSetString(&map, "message", "test")) {
		KLog(LError, "JsonMapSetString failed");
		goto cleanup;
	}

	if (JsonMapSetLong(&map, "counter", -1)) {
		KLog(LError, "JsonMapSetLong failed");
		goto cleanup;
	}

	if (JsonMapSetUlong(&map, "total", 200)) {
		KLog(LError, "JsonMapSetUlong failed");
		goto cleanup;
	}

	encoded = JsonMapDumps(&map);
	if (encoded == NULL) {
		KLog(LError, "JsonMapDumps failed");
		goto cleanup;
	}

	KLog(LInfo, "encoded json=%s", encoded);

cleanup:
	if (encoded != NULL)
		JsonFree(encoded);

	JsonMapRelease(&map);
}

void JsonInit()
{
	json_set_alloc_funcs(JsonAlloc, JsonFree);
	JsonSelfTest();
}

