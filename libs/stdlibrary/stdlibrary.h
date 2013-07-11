#ifndef __STDLIBRARY_H__
#define __STDLIBRARY_H__

#ifdef __cplusplus
extern "C" {
#endif
#include <ntifs.h>
#ifdef __cplusplus
}
#endif

void * malloc ( size_t size );
void free( void * ptr );
unsigned char rand();

#endif
