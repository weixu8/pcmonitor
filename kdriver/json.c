#include <inc/json.h>
#include <inc/klogger.h>
#include <inc/string.h>

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

int JsonMapInit(PJSON_MAP map)
{
	RtlZeroMemory(map, sizeof(JSON_MAP));
	map->object = json_object();
	if (map->object == NULL)
		return -1;
	return 0;
}

void JsonMapRelease(PJSON_MAP map)
{
	if (map->object != NULL)
		json_decref(map->object);
	map->object = NULL;
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

char *JsonMapGetString(PJSON_MAP map, const char *key)
{
	json_t *value_t = NULL;
	const char *string = NULL;
	char *stringCopy = NULL;

	value_t = json_object_get(map->object, key);
	if (value_t == NULL)
		return NULL;

	if (!json_is_string(value_t))
		goto cleanup;
	
	string = json_string_value(value_t);
	if (string != NULL) {
		stringCopy = CRtlCopyStr(string);
	}

cleanup:

	return stringCopy;
}

int JsonMapGetUlong(PJSON_MAP map, const char *key, PULONG pvalue)
{
	json_t *value_t = NULL;
	char *string = NULL;
	char *stringCopy = NULL;
	ULONG value = -1;
	int res = -1;
	NTSTATUS Status;

	value_t = json_object_get(map->object, key);
	if (value_t == NULL)
		goto cleanup;

	if (json_typeof(value_t) == JSON_STRING) {
		const char *svalue = json_string_value(value_t);
		if (svalue == NULL)
			goto cleanup;

		Status = RtlCharToInteger(svalue, 10, pvalue);
		if (!NT_SUCCESS(Status)) {
			KLog(LError, "svalue=%s to int failed with err=%x", svalue, Status);
			goto cleanup;
		}
	} else {
		if (json_typeof(value_t) != JSON_INTEGER)
			goto cleanup;
		*pvalue = (ULONG)json_integer_value(value_t);
	}

	res = 0;

cleanup:

	return res;
}

int JsonMapGetLong(PJSON_MAP map, const char *key, PLONG pvalue)
{
	json_t *value_t = NULL;
	char *string = NULL;
	char *stringCopy = NULL;
	ULONG value = -1;
	int res = -1;
	NTSTATUS Status;

	value_t = json_object_get(map->object, key);
	if (value_t == NULL)
		goto cleanup;

	if (json_typeof(value_t) == JSON_STRING) {
		const char *svalue = json_string_value(value_t);
		if (svalue == NULL)
			goto cleanup;

		Status = RtlCharToInteger(svalue, 10, (PULONG)pvalue);
		if (!NT_SUCCESS(Status)) {
			KLog(LError, "svalue=%s to int failed with err=%x", svalue, Status);
			goto cleanup;
		}

	} else {
		if (json_typeof(value_t) != JSON_INTEGER)
			goto cleanup;
		*pvalue = (LONG)json_integer_value(value_t);
	}

	res = 0;
cleanup:

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

	if (JsonMapInit(&map)) {
		KLog(LError, "JsonMapInit failed");
		goto cleanup;
	}

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


int JsonMapLoads(PJSON_MAP map, const char *json)
{
	json_error_t error;

	JsonMapRelease(map);
	map->object = json_loads(json, 0, &error);
	if (map->object == NULL)
		return -1;
	return 0;
}

void JsonInit()
{
	json_set_alloc_funcs(JsonAlloc, JsonFree);
	JsonSelfTest();
}

