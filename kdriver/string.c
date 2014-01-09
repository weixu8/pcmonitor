#include <inc\string.h>


NTSTATUS
CRtlUnicodeStringCopyToSZ(IN PUNICODE_STRING Src, OUT PUNICODE_STRING pDst, ULONG Tag)
{
	UNICODE_STRING Dst = { 0, 0, NULL };

	Dst.Buffer = ExAllocatePoolWithTag(NonPagedPool, Src->MaximumLength + sizeof(WCHAR), Tag);
	if (Dst.Buffer == NULL)
		return STATUS_NO_MEMORY;

	RtlCopyMemory(Dst.Buffer, Src->Buffer, Src->MaximumLength);

	Dst.Length = Src->Length;
	Dst.MaximumLength = Src->MaximumLength + sizeof(WCHAR);

	Dst.Buffer[Src->MaximumLength / sizeof(WCHAR)] = L'\0';
	*pDst = Dst;

	return STATUS_SUCCESS;
}

VOID
CRtlUnicodeStringFreeAndZero(IN PUNICODE_STRING Src)
{
	if (Src->Buffer != NULL)
		ExFreePool(Src->Buffer);

	RtlZeroMemory(Src, sizeof(UNICODE_STRING));
}
