//I reverse-engineered the compiler generated exception handler function and thats how it looks:

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
