
IFDEF RAX

	STUB_DATA				struc
	Inited					dq		?
	libName					dw		100h dup (?)
	Kernel32Name			dw		20h dup (?)
	VirtualProtectName		db		20h dup (?)
	bLoadLibraryEx			db		?
	pLoadLibraryW			dq		?
	pGetProcAddress			dq		?
	VirtualProtect			dq		?
	STUB_DATA			ends

	.CODE
	stubStart:
	stubData STUB_DATA <>
	stubProcedure PROC
		push rbx
		mov rbx, 1
		mov rax, 0
		lock cmpxchg [stubData.Inited], rbx
		jnz cleanup
		int 3
cleanup:
		pop rbx
		ret
	stubProcedure ENDP
	stubEnd:
ELSE
	.686
	.MODEL FLAT, STDCALL

	STUB_DATA				struc
	Inited					dd		?
	libName					dw		100h dup (?)
	Kernel32Name			dw		20h dup (?)
	VirtualProtectName		db		20h dup (?)
	bLoadLibraryEx			db		?
	pLoadLibraryW			dd		?
	pGetProcAddress			dd		?
	VirtualProtect			dd		?
	STUB_DATA			ends

	.CODE
	stubStart:
	stubData STUB_DATA <>
	stubProcedure PROC
		push ebx
		push ebp
		mov ebp, esp
		mov ebx, 1
		mov eax, 0
		lock cmpxchg [stubData.Inited], ebx
		jnz cleanup
		int 3
cleanup:
		mov esp, ebp
		pop ebp
		pop ebx
		ret
	stubProcedure ENDP
	stubEnd:
ENDIF
	.DATA
	public stubStart
	public stubSize
	stubSize dq stubEnd - stubStart
END