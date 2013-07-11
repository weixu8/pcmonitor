#include "stdlibrary.h"

#define MODULE_TAG 'stdl'


void * malloc ( size_t size )
{
    return ExAllocatePoolWithTag(NonPagedPool, size, MODULE_TAG);
}

void free( void * ptr )
{
    ExFreePoolWithTag(ptr, MODULE_TAG);
}

unsigned char rand()
{
    __debugbreak();
    return 0;
}

