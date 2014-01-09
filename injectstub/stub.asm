
IFDEF RAX
	STUB_DATA			struc
	Inited				dq		?
	LdrLoadDll			dq ?
	usDllName_Length dd ?
	uDllName_MaximumLength dd ?
	usDllName_Buffer	dq ?	
	DllName				dw		100h dup (?)
	DllPath				dw		100h dup (?)
	hModule				dq ?
	Loaded				dq ?
	STUB_DATA			ends

	.CODE
	stubStart:
	stubData STUB_DATA <>
	stubProcedure PROC
		push rbx
		push rax
		mov rbx, 1
		mov rax, 0
		lock cmpxchg [stubData.Inited], rbx
		jnz cleanup
		mov		rax, qword ptr [stubData.LdrLoadDll]
		lea		rcx, [stubData.DllPath] 
		xor rdx, rdx
		lea		r8, [stubData.usDllName_Length]
		lea		r9, [stubData.hModule]
		call	rax
		or		rax, rax
		jnz cleanup
		mov rax, 1
		mov [stubData.Loaded], rax
cleanup:
		pop rax
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