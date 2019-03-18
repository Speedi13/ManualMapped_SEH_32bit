# ManualMapped SEH on x86-32Bit
Enable SEH support for manual mapped x86-32bit PEs <br /> <br />
**Notice**: SEH only works on x86-32bit the way it is described below<br />

# What is the problem?
When you manually map a PE-File (such as a DLL) the exception handlers won't work, so the whole program crashes when an exception occurs.<br />
Code example of a SEH exception handler in c++:<br />
```cpp
__try{
	*(DWORD*)0x123 = 0x1337; // will crash
}__except(1){
	MessageBoxA( 0, "__except","__except",0);
};
```
<br />So I will explain how it works and how you can get it to work in your manual mapped code:
<br />
# How SEH (v4) works in 32bit
The SEH v4 structs<br />
```cpp
struct EH4_SCOPETABLE_RECORD
{
  int EnclosingLevel;
  void *FilterFunc;
  void *HandlerFunc;
};

struct EH4_SCOPETABLE
{
  int GSCookieOffset;
  int GSCookieXOROffset;
  int EHCookieOffset;
  int EHCookieXOROffset;
  struct EH4_SCOPETABLE_RECORD ScopeRecord[];
};

struct EH4_EXCEPTION_REGISTRATION_RECORD
{
  void *SavedESP;
  EXCEPTION_POINTERS *ExceptionPointers;
  EXCEPTION_REGISTRATION_RECORD SubRecord;
  EH4_SCOPETABLE* EncodedScopeTable; //Xored with the __security_cookie
  unsigned int TryLevel;
};
```


At the beginning of each function the **EH4_EXCEPTION_REGISTRATION_RECORD** for the SEH handler gets pushed on to the stack:<br />
```asm
push    ebp
mov     ebp, esp
push    0FFFFFFFEh
push    offset stru_1000E0E8 ; <= EH4_SCOPETABLE
push    offset __except_handler4 ; <= the actual handler function address gets stored on the stack
mov     eax, large fs:0
push    eax
sub     esp, 8
push    ebx
push    esi
push    edi
mov     eax, ___security_cookie
xor     [ebp+ms_exc.EncodedScopeTable], eax ; <= pointer gets xored (not in v3 or even lower version)
xor     eax, ebp
push    eax
lea     eax, [ebp+ms_exc.SubRecord]
mov     large fs:0, eax ; <= the address of the EXCEPTION_REGISTRATION_RECORD gets stored in the segment register fs
mov     [ebp+ms_exc.SavedESP], esp
```
<br />
Now to the actual exception part:<br />

```asm
;   __try { // __except at $LN7
	mov     [ebp+ms_exc.TryLevel], 0
	mov     large dword ptr ds:123h, 1337h ; <= test code that will cause a 0xC0000005 exception
;                                                   In c++: *(DWORD*)0x123 = 0x1337;
	jmp     short loc_100010C0 ; <= jumps to the end
; ---------------------------------------------------------------------------

$LN6:
;   __except filter // owned by 10001090 ;
	mov     eax, 1

$LN14:
	retn
; ---------------------------------------------------------------------------

$LN7:
;   __except($LN6) // owned by 10001090
; when a exception occurred it will open a messagebox
	mov     esp, [ebp+ms_exc.SavedESP]
	push    0               ; uType
	push    offset Caption  ; "__except"
	push    offset Caption  ; "__except"
	push    0               ; hWnd
	call    ds:__imp__MessageBoxA@16 ; MessageBoxA(x,x,x,x)
;   } // starts at 10001090

loc_100010C0: ; << end of the try-except region
mov     [ebp+ms_exc.TryLevel], 0FFFFFFFEh
```


Now if we look at the **EH4_SCOPETABLE** struct we see the jump marks again:<br />

```asm
.rdata:1000E0E8 stru_1000E0E8   dd 0FFFFFFFEh           ; GSCookieOffset ; SEH scope table for function 10001050
.rdata:1000E0E8                 dd 0                    ; GSCookieXOROffset
.rdata:1000E0E8                 dd 0FFFFFFD8h           ; EHCookieOffset
.rdata:1000E0E8                 dd 0                    ; EHCookieXOROffset
.rdata:1000E0E8                 dd 0FFFFFFFEh           ; ScopeRecord.EnclosingLevel
.rdata:1000E0E8                 dd offset $LN6          ; ScopeRecord.FilterFunc
.rdata:1000E0E8                 dd offset $LN7          ; ScopeRecord.HandlerFunc
```

<br />

# MSVC's __except_handler4 function

I reverse-engineered the compiler generated exception handler function and thats how it looks:<br />

<details>
	<summary>>><big>click to show the functions code</big><<</summary>
	
```cpp
#define EH_EXCEPTION_NUMBER ('msc' | 0xE0000000)

EXCEPTION_DISPOSITION __cdecl _except_handler4(_EXCEPTION_RECORD *ExceptionRecord, EXCEPTION_REGISTRATION_RECORD *EstablisherFrame, _CONTEXT *ContextRecord, PVOID DispatcherContext)
{
	EH4_EXCEPTION_REGISTRATION_RECORD* EH4 = CONTAINING_RECORD( EstablisherFrame, EH4_EXCEPTION_REGISTRATION_RECORD, SubRecord );
	void* EH4_END = EH4+1;

	EH4_SCOPETABLE* ScopeTable = (EH4_SCOPETABLE *)(__security_cookie ^ (DWORD)EH4->EncodedScopeTable);
	/////////////////////////////////////////////////////////////////////////////////////////////////
	//Stack integrity checks:
	if ( ScopeTable->GSCookieOffset != -2 )
		__security_check_cookie(	*(DWORD*)(ScopeTable->GSCookieXOROffset +	(DWORD)EH4_END)
				/*XOR*/	^	*(DWORD*)(ScopeTable->GSCookieOffset +		(DWORD)EH4_END) );

	__security_check_cookie(	*(DWORD*)(ScopeTable->EHCookieXOROffset +	(DWORD)EH4_END)
			/*XOR*/	^	*(DWORD*)(ScopeTable->EHCookieOffset +		(DWORD)EH4_END) );
	/////////////////////////////////////////////////////////////////////////////////////////////////

	EXCEPTION_DISPOSITION HandlerResult = ExceptionContinueSearch;

	if ( ExceptionRecord->ExceptionFlags & 0x66 )
	{
		if ( EH4->TryLevel == -2 )
			return ExceptionContinueSearch;
		_EH4_LocalUnwind((DWORD)EstablisherFrame, -2, (DWORD)EH4_END, (DWORD)&__security_cookie);
	}
	else
	{
		EXCEPTION_POINTERS ExceptionPointers = {};
		ExceptionPointers.ExceptionRecord = ExceptionRecord;
		ExceptionPointers.ContextRecord = ContextRecord;
		EH4->ExceptionPointers = &ExceptionPointers;

		bool v13 = false;

		DWORD LastTryLevel = EH4->TryLevel;
		if ( LastTryLevel == -2 )
			return ExceptionContinueSearch;
		do
		{
			void* FilterFunc = ScopeTable->ScopeRecord[LastTryLevel].FilterFunc;
			int EnclosingLevel = ScopeTable->ScopeRecord[LastTryLevel].EnclosingLevel;
			EH4_SCOPETABLE_RECORD* pScopeRecord = &ScopeTable->ScopeRecord[LastTryLevel];
			if ( FilterFunc )
			{
				int FilterResult = _EH4_CallFilterFunc(FilterFunc, EH4_END);
				v13 = true;
				if ( FilterResult < 0 )
				{
					HandlerResult = ExceptionContinueExecution;
					goto LABEL_23;
				}
				if ( FilterResult > 0 )
				{
					if ( ExceptionRecord->ExceptionCode == EH_EXCEPTION_NUMBER
						&& _pDestructExceptionObject
						&& _IsNonwritableInCurrentImage((char *)&_pDestructExceptionObject) )
					{
						_pDestructExceptionObject(ExceptionRecord, 1);
					}
					_EH4_GlobalUnwind2(EstablisherFrame, ExceptionRecord);
					
					if ( EH4->TryLevel != LastTryLevel )
					{
						_EH4_LocalUnwind(EH4_END, &__security_cookie);
					}
					EH4->TryLevel = EnclosingLevel;
					/////////////////////////////////////////////////////////////////////////////////////////////////
					//Stack integrity checks:
					if ( ScopeTable->GSCookieOffset != -2 )
						__security_check_cookie(	*(DWORD*)(ScopeTable->GSCookieXOROffset +	(DWORD)EH4_END)
								/*XOR*/	^	*(DWORD*)(ScopeTable->GSCookieOffset +		(DWORD)EH4_END) );

					__security_check_cookie(	*(DWORD*)(ScopeTable->EHCookieXOROffset +	(DWORD)EH4_END)
							/*XOR*/	^	*(DWORD*)(ScopeTable->EHCookieOffset +		(DWORD)EH4_END) );
					/////////////////////////////////////////////////////////////////////////////////////////////////
					_EH4_TransferToHandler(pScopeRecord->HandlerFunc, EH4_END);
					__debugbreak();
					_crt_debugger_hook();
				}
			}
			else
			{
				v13 = true;
			}
			LastTryLevel = EnclosingLevel;
		}
		while ( LastTryLevel != -2 );
		if ( !v13 )
			return HandlerResult;
	}
LABEL_23:
	/////////////////////////////////////////////////////////////////////////////////////////////////
	//Stack integrity checks:
	if ( ScopeTable->GSCookieOffset != -2 )
		__security_check_cookie(	*(DWORD*)(ScopeTable->GSCookieXOROffset +	(DWORD)EH4_END)
								 ^	*(DWORD*)(ScopeTable->GSCookieOffset +		(DWORD)EH4_END) );

	__security_check_cookie(	*(DWORD*)(ScopeTable->EHCookieXOROffset +	(DWORD)EH4_END)
			/*XOR*/	 ^	*(DWORD*)(ScopeTable->EHCookieOffset +		(DWORD)EH4_END) );
	/////////////////////////////////////////////////////////////////////////////////////////////////
	return HandlerResult;
}
```

</details>

<br />
so this compiler generated function already does the heavy lifting

# Calling the compiler generated exception handler function
for doing that you have to implement an exception handler <br />which can be done easily form manual mapped code by calling [AddVectoredExceptionHandler](https://msdn.microsoft.com/en-us/library/windows/desktop/ms679274(v=vs.85).aspx) <br />

making sure to only process exceptions from the manual mapped code:<br />
```cpp
g_ImageStartAddr = &__ImageBase;
g_ImageEndAddr = (char*)g_ImageStartAddr + GetSizeOfImage();
```

<br />

```cpp
AddVectoredExceptionHandler( 1, ExceptionHandler );
```
The code for the exception handler:
<br />
```cpp
LONG NTAPI ExceptionHandler(_EXCEPTION_POINTERS *ExceptionInfo)
{
	//making sure to only process exceptions from the manual mapped code:
	PVOID ExceptionAddress = ExceptionInfo->ExceptionRecord->ExceptionAddress;
	if ( ExceptionAddress < g_ImageStartAddr || ExceptionAddress > g_ImageEndAddr )
		return EXCEPTION_CONTINUE_SEARCH;
	
	EXCEPTION_REGISTRATION_RECORD* pFs = (EXCEPTION_REGISTRATION_RECORD*) __readfsdword( 0 ); // mov pFs, large fs:0 ; <= reading from the segment register
	if ( (DWORD_PTR)pFs > 0x1000 && (DWORD_PTR)pFs < 0xFFFFFFF0 ) //validate pointer
	{
		EH4_EXCEPTION_REGISTRATION_RECORD* EH4 = CONTAINING_RECORD( pFs, EH4_EXCEPTION_REGISTRATION_RECORD, SubRecord );
		EXCEPTION_ROUTINE* EH4_ExceptionHandler = EH4->SubRecord.Handler;

		if ( EH4_ExceptionHandler > g_ImageStartAddr && EH4_ExceptionHandler < g_ImageEndAddr )//validate pointer
		{
			//calling the compiler generated function to do the work :D
			EXCEPTION_DISPOSITION ExceptionDisposition = EH4_ExceptionHandler( ExceptionInfo->ExceptionRecord, &EH4->SubRecord, ExceptionInfo->ContextRecord, nullptr ); 
			if ( ExceptionDisposition == ExceptionContinueExecution )
				return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}
```
