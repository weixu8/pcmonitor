#include <inc\string.h>

#define MODULE_TAG 'strg'

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



#define LONG_MIN (-2147483647 - 1)
#define LONG_MAX 2147483647
#define ULONG_MAX 4294967295

static FORCEINLINE int
isupper_(char c)
{
	return (c >= 'A' && c <= 'Z');
}

static FORCEINLINE int
isalpha_(char c)
{
	return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}


static FORCEINLINE int
isspace_(char c)
{
	return (c == ' ' || c == '\t' || c == '\n' || c == '\12');
}

static FORCEINLINE int
isdigit_(char c)
{
	return (c >= '0' && c <= '9');
}

/*
* Convert a string to a long integer.
*
* Ignores `locale' stuff.  Assumes that the upper and lower case
* alphabets and digits are each contiguous.
*/
long
strtol(nptr, endptr, base)
const char *nptr;
char **endptr;
register int base;
{
	register const char *s = nptr;
	register unsigned long acc;
	register char c;
	register unsigned long cutoff;
	register int neg = 0, any, cutlim;
	long result = 0;

	/*
	* Skip white space and pick up leading +/- sign if any.
	* If base is 0, allow 0x for hex and 0 for octal, else
	* assume decimal; if base is already 16, allow 0x.
	*/
	do {
		c = *s++;
	} while (isspace_(c));
	if (c == '-') {
		neg = 1;
		c = *s++;
	}
	else if (c == '+')
		c = *s++;
	if ((base == 0 || base == 16) &&
		c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		base = 16;
	}
	else if ((base == 0 || base == 2) &&
		c == '0' && (*s == 'b' || *s == 'B')) {
		c = s[1];
		s += 2;
		base = 2;
	}
	if (base == 0)
		base = c == '0' ? 8 : 10;

	/*
	* Compute the cutoff value between legal numbers and illegal
	* numbers.  That is the largest legal value, divided by the
	* base.  An input number that is greater than this value, if
	* followed by a legal input character, is too big.  One that
	* is equal to this value may be valid or not; the limit
	* between valid and invalid numbers is then based on the last
	* digit.  For instance, if the range for longs is
	* [-2147483648..2147483647] and the input base is 10,
	* cutoff will be set to 214748364 and cutlim to either
	* 7 (neg==0) or 8 (neg==1), meaning that if we have accumulated
	* a value > 214748364, or equal but the next digit is > 7 (or 8),
	* the number is too big, and we will return a range error.
	*
	* Set any if any `digits' consumed; make it negative to indicate
	* overflow.
	*/
	cutoff = neg ? -LONG_MIN : LONG_MAX;
	cutlim = cutoff % (unsigned long)base;
	cutoff /= (unsigned long)base;
	for (acc = 0, any = 0;; c = *s++) {
		if (isdigit(c))
			c -= '0';
		else if (isalpha_(c))
			c -= isupper_(c) ? 'A' - 10 : 'a' - 10;
		else
			break;
		if (c >= base)
			break;
		if (any < 0 || acc > cutoff || acc == cutoff && c > cutlim)
			any = -1;
		else {
			any = 1;
			acc *= base;
			acc += c;
		}
	}
	
	if (any < 0) {
		result = neg ? LONG_MIN : LONG_MAX;
		//		errno = ERANGE;
	}
	else if (neg)
		result = -((long)acc);
	if (endptr != 0)
		*endptr = (char *)(any ? s - 1 : nptr);
	return (result);
}

/*
* Convert a string to an unsigned long integer.
*
* Ignores `locale' stuff.  Assumes that the upper and lower case
* alphabets and digits are each contiguous.
*/
unsigned long
strtoul(nptr, endptr, base)
const char *nptr;
char **endptr;
register int base;
{
	register const char *s = nptr;
	register unsigned long acc;
	register char c;
	register unsigned long cutoff;
	register int neg = 0, any, cutlim;
	unsigned long result;

	/*
	* See strtol for comments as to the logic used.
	*/
	do {
		c = *s++;
	} while (isspace_(c));
	if (c == '-') {
		neg = 1;
		c = *s++;
	}
	else if (c == '+')
		c = *s++;
	if ((base == 0 || base == 16) &&
		c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		base = 16;
	}
	else if ((base == 0 || base == 2) &&
		c == '0' && (*s == 'b' || *s == 'B')) {
		c = s[1];
		s += 2;
		base = 2;
	}
	if (base == 0)
		base = c == '0' ? 8 : 10;
	cutoff = (unsigned long)ULONG_MAX / (unsigned long)base;
	cutlim = (unsigned long)ULONG_MAX % (unsigned long)base;
	for (acc = 0, any = 0;; c = *s++) {
		if (isdigit(c))
			c -= '0';
		else if (isalpha_(c))
			c -= isupper_(c) ? 'A' - 10 : 'a' - 10;
		else
			break;
		if (c >= base)
			break;
		if (any < 0 || acc > cutoff || acc == cutoff && c > cutlim)
			any = -1;
		else {
			any = 1;
			acc *= base;
			acc += c;
		}
	}
	if (any < 0) {
		result = ULONG_MAX;
		//		errno = ERANGE;
	}
	else if (neg)
		result = -((long)acc);
	if (endptr != 0)
		*endptr = (char *)(any ? s - 1 : nptr);
	return (result);
}


char *CRtlCopyStr(const char *str)
{
	size_t len = strlen(str) + 1;
	char *copy = NULL;

	copy = ExAllocatePoolWithTag(NonPagedPool, len, MODULE_TAG);
	if (copy != NULL) {
		RtlCopyMemory(copy, str, len);
	}

	return copy;
}