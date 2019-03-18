#include <Windows.h>
#if !defined(_X86_)
#error Only on 32bit it works this way
#endif

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


//to access the global PE variables:
extern "C" LPVOID __ImageBase;
extern "C" ULONG_PTR __security_cookie;

DWORD GetSizeOfImage( void );

void* g_ImageStartAddr = nullptr;
void* g_ImageEndAddr = nullptr;

LONG NTAPI ExceptionHandler(_EXCEPTION_POINTERS *ExceptionInfo)
{
	//making sure to only process exceptions from the manual mapped code:
	PVOID ExceptionAddress = ExceptionInfo->ExceptionRecord->ExceptionAddress;
	if ( ExceptionAddress < g_ImageStartAddr || ExceptionAddress > g_ImageEndAddr )
		return EXCEPTION_CONTINUE_SEARCH;
	
	EXCEPTION_REGISTRATION_RECORD* pFs = (EXCEPTION_REGISTRATION_RECORD*) __readfsdword( 0 ); // mov pFs, large fs:0 ; <= reading the segment register
	if ( (DWORD_PTR)pFs > 0x1000 && (DWORD_PTR)pFs < 0xFFFFFFF0 ) //validate pointer
	{
		EH4_EXCEPTION_REGISTRATION_RECORD* EH4 = CONTAINING_RECORD( pFs, EH4_EXCEPTION_REGISTRATION_RECORD, SubRecord );
		
		EXCEPTION_ROUTINE* EH4_ExceptionHandler = EH4->SubRecord.Handler;
		if ( EH4_ExceptionHandler > g_ImageStartAddr && EH4_ExceptionHandler < g_ImageEndAddr ) //validate pointer
		{
			//calling the compiler generated function to do the work :D
			EXCEPTION_DISPOSITION ExceptionDisposition = EH4_ExceptionHandler( ExceptionInfo->ExceptionRecord, &EH4->SubRecord,	ExceptionInfo->ContextRecord, nullptr );
			if ( ExceptionDisposition == ExceptionContinueExecution )
				return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

DWORD __stdcall MainThread( LPVOID lpvReserved )
{
	UNREFERENCED_PARAMETER( lpvReserved );
  	
	g_ImageStartAddr = &__ImageBase;
	g_ImageEndAddr = (char*)g_ImageStartAddr + GetSizeOfImage();
	
	//Register the exception handler:
	AddVectoredExceptionHandler( 1, ExceptionHandler );
  
__try{
	*(DWORD*)0x123 = 0x1337;
}__except(EXCEPTION_EXECUTE_HANDLER){
	MessageBoxA( 0, "__except","__except",0);
};
	return TRUE;
}

DWORD APIENTRY DllMain (HMODULE hModule, DWORD dwReason, LPVOID lpvReserved	)
{
	if (dwReason == DLL_PROCESS_ATTACH)
		CreateThread( NULL, NULL, MainThread, lpvReserved, NULL, NULL );

	return TRUE;
}

DWORD GetSizeOfImage( void )
{
	IMAGE_DOS_HEADER* ImageDosHeader = (IMAGE_DOS_HEADER*)&__ImageBase;
	if ( !ImageDosHeader || ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE )
		return NULL;

	IMAGE_NT_HEADERS* ImageNtHeaders = (PIMAGE_NT_HEADERS)( (char*)ImageDosHeader + ImageDosHeader->e_lfanew );
	if ( ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE  )
		return NULL;

	return ImageNtHeaders->OptionalHeader.SizeOfImage;
}

#pragma region _EHStructs

struct SCOPETABLE_ENTRY
{
  unsigned int enclosing_level;
  unsigned int filter;
  unsigned int specific_handler;
};

struct EXCEPTION_REGISTRATION_COMMON
{
  BYTE gap0[8];
  unsigned int scopetable;
  unsigned int trylevel;
};

struct EH3_EXCEPTION_REGISTRATION
{
  struct EH3_EXCEPTION_REGISTRATION *Next;
  EXCEPTION_ROUTINE* ExceptionHandler;
  SCOPETABLE_ENTRY* ScopeTable;
  DWORD TryLevel;
};

struct CPPEH_RECORD
{
  DWORD old_esp;
  EXCEPTION_POINTERS *exc_ptr;
  EH3_EXCEPTION_REGISTRATION registration;
};

struct EXCEPTION_REGISTRATION
{
  unsigned int prev;
  unsigned int handler;
};
#pragma endregion EHStructs
