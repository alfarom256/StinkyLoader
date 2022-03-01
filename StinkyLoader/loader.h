#pragma once
#include <Windows.h>
#include <winnt.h>
#include <winternl.h>
#include "PebLdrInline.h"

#define MAXIMUM_HEADER_SEARCH_BYTES 0x3000

typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef LPVOID(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI* pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL(WINAPI* pFlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);
typedef NTSTATUS(WINAPI* pLdrGetProcedureAddress)(HMODULE, PANSI_STRING, WORD, PVOID);
typedef VOID(WINAPI* pRtlInitAnsiString)(PANSI_STRING, PCSZ);
#ifdef _WIN64
typedef BOOL(WINAPI* pRtlAddFunctionTable)(PRUNTIME_FUNCTION, DWORD, DWORD64);
#endif
typedef BOOL(WINAPI* pDllMain)(HINSTANCE, DWORD, LPVOID);
typedef void (WINAPI* pGetNativeSystemInfo)(LPSYSTEM_INFO);
typedef BOOL(WINAPI* pVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef HANDLE(WINAPI* pCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);


// https://github.com/fancycode/MemoryModule/blob/master/MemoryModule.c#L123
static __forceinline size_t
AlignValueUp(size_t value, size_t alignment) {
	return (value + alignment - 1) & ~(alignment - 1);
}

// https://github.com/monoxgas/sRDI/blob/master/ShellcodeRDI/ShellcodeRDI.c#L73
#pragma warning( push )
#pragma warning( disable : 4214 ) // nonstandard extension
typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;
#pragma warning(pop)


// BEGIN LOADER FUNCTION
#pragma intrinsic(memcpy)
#pragma runtime_checks("", off)
__declspec(code_seg(".shlc"))
__declspec(guard(ignore))
__declspec(safebuffers)
uintptr_t load(uintptr_t current_base) {
	// find the offset of the payload from our reflective loader prelude
	DWORD cbPeHeaderOffset = 0;
	uintptr_t old_base_addr = current_base;
	while (cbPeHeaderOffset < MAXIMUM_HEADER_SEARCH_BYTES) {
		if (IS_PE_MAGIC(*(WORD*)old_base_addr)) {
			break;
		}
		old_base_addr++;
	}
	if (cbPeHeaderOffset == MAXIMUM_HEADER_SEARCH_BYTES)
	{
		return -31;
	}

	// begin initialize loader data
	uintptr_t k32base = (uintptr_t)getK32();
	uintptr_t ntbase = (uintptr_t)getNtdll();

	LDR_DATA ldrKernel32 = { 0 };
	LDR_DATA ldrNtdll = { 0 };

	if (!init_ldr_data(&ldrKernel32, (HMODULE)k32base)) {
		return -1;
	}

	if (!init_ldr_data(&ldrNtdll, (HMODULE)ntbase)) {
		return -1;
	}

	// end initialize loader data

	PIMAGE_SECTION_HEADER section = NULL;
	uintptr_t address_of_entry = 0;
	LPVOID new_module_base = NULL;
	uintptr_t baseOffset = 0;


	// kernel32
	constexpr DWORD cdwVirtualAlloc = cexpr_adler32("VirtualAlloc");
	constexpr DWORD cdwVirtualFree = cexpr_adler32("VirtualFree");
	constexpr DWORD cdwLoadLibraryA = cexpr_adler32("LoadLibraryA");
	constexpr DWORD cdwGetProcAddress = cexpr_adler32("GetProcAddress");
	constexpr DWORD cdwVirtualProtect = cexpr_adler32("VirtualProtect");
	constexpr DWORD cdwFlushInstructionCache = cexpr_adler32("FlushInstructionCache");
	constexpr DWORD cdwGetNativeSystemInfo = cexpr_adler32("GetNativeSystemInfo");
	constexpr DWORD cdwCreateThread = cexpr_adler32("CreateThread");

	// ntdll
	constexpr DWORD cdwRtlInitAnsiString = cexpr_adler32("RtlInitAnsiString");
	constexpr DWORD cdwLdrGetProcedureAddress = cexpr_adler32("LdrGetProcedureAddress");

#ifdef _WIN64
	constexpr DWORD cdwRtlAddFunctionTable = cexpr_adler32("RtlAddFunctionTable");
	pRtlAddFunctionTable stubRtlAddFunctionTable = NULL;
#endif

	pLoadLibraryA stubLoadLibraryA = NULL;
	pGetProcAddress stubGetProcAddress = NULL;
	pVirtualProtect stubVirtualProtect = NULL;
	pFlushInstructionCache stubFlushInstructionCache = NULL;
	pRtlInitAnsiString stubRtlInitAnsiString = NULL;
	pLdrGetProcedureAddress stubLdrGetProcedureAddress = NULL;
	pVirtualAlloc stubVirtualAlloc = NULL;
	pVirtualFree stubVirtualFree = NULL;
	pGetNativeSystemInfo stubGetNativeSystemInfo = NULL;
	pCreateThread stubCreateThread = NULL;

	SYSTEM_INFO SystemInfo = { 0 };

	IMAGE_DATA_DIRECTORY dataDir;

	PPEB ppeb = NULL;

	IMAGE_DOS_HEADER* _old_dos_hdr = NULL;
	IMAGE_NT_HEADERS* _old_nt_hdr = NULL;
	IMAGE_EXPORT_DIRECTORY* _old_export_dir = NULL;

	IMAGE_DOS_HEADER* _new_dos_hdr = NULL;
	IMAGE_NT_HEADERS* _new_nt_hdr = NULL;
	IMAGE_EXPORT_DIRECTORY* _new_export_dir = NULL;

	PDWORD funcTbl = NULL;
	PWORD ordTbl = NULL;
	PVOID nameTbl = NULL;
	DWORD num_exp = 0;


	/*
	======================================================
	IMPORTING NEEDED FUNCTIONS FROM K32
	======================================================
	*/

	stubLoadLibraryA = (pLoadLibraryA)get_from_ldr_data(&ldrKernel32, cdwLoadLibraryA);
	if (!stubLoadLibraryA)
		return -40;
	
	stubGetProcAddress = (pGetProcAddress)get_from_ldr_data(&ldrKernel32, cdwGetProcAddress);
	if (!stubGetProcAddress)
		return -41;
	
	stubVirtualProtect = (pVirtualProtect)get_from_ldr_data(&ldrKernel32, cdwVirtualProtect);
	if (!stubVirtualProtect)
		return -42;
	
	stubFlushInstructionCache = (pFlushInstructionCache)get_from_ldr_data(&ldrKernel32, cdwFlushInstructionCache);
	if (!stubFlushInstructionCache)
		return -43;
	
	stubGetNativeSystemInfo = (pGetNativeSystemInfo)get_from_ldr_data(&ldrKernel32, cdwGetNativeSystemInfo);
	if (!stubGetNativeSystemInfo)
		return -44;
	
	stubVirtualFree = (pVirtualFree)get_from_ldr_data(&ldrKernel32, cdwVirtualFree);
	if (!stubVirtualFree)
		return -45;
	
	stubVirtualAlloc = (pVirtualAlloc)get_from_ldr_data(&ldrKernel32, cdwVirtualAlloc);
	if (!stubVirtualAlloc)
		return -46;
	
	stubCreateThread = (pCreateThread)get_from_ldr_data(&ldrKernel32, cdwCreateThread);
	if (!stubCreateThread)
		return -47;


	/*
	======================================================
	IMPORTING NEEDED FUNCTIONS FROM NTDLL
	======================================================
	*/

	stubRtlInitAnsiString = (pRtlInitAnsiString)get_from_ldr_data(&ldrNtdll, cdwRtlInitAnsiString);
	if (!stubRtlInitAnsiString)
		return -48;
	stubLdrGetProcedureAddress = (pLdrGetProcedureAddress)get_from_ldr_data(&ldrNtdll, cdwLdrGetProcedureAddress);
	if (!stubLdrGetProcedureAddress)
		return -49;
#ifdef _WIN64
	stubRtlAddFunctionTable = (pRtlAddFunctionTable)get_from_ldr_data(&ldrNtdll, cdwRtlAddFunctionTable);
	if (!stubRtlAddFunctionTable)
		return -50;
#endif


	/* ====================================================================================================================================================
	* 1. Ensure the aligned image size (using OptionalHeader aligned to sys) is equal to the calculated last section's end aligned to the system alignment.
	==================================================================================================================================================== */


	_old_dos_hdr = (IMAGE_DOS_HEADER*)old_base_addr;
	if (!IS_PE_MAGIC(_old_dos_hdr->e_magic)) {
		return -7;
	}

	_old_nt_hdr = (IMAGE_NT_HEADERS*)((uintptr_t)old_base_addr + _old_dos_hdr->e_lfanew);
	if (_old_nt_hdr->Signature != IMAGE_NT_SIGNATURE) {
		return -8;
	}

	// https://github.com/fancycode/MemoryModule/blob/master/MemoryModule.c#L597
	section = IMAGE_FIRST_SECTION(_old_nt_hdr);
	DWORD optionalSectionSize = _old_nt_hdr->OptionalHeader.SectionAlignment;
	size_t lastSectionEnd = 0;

	// make sure we account for overwriting this data
	for (size_t i = 0; i < _old_nt_hdr->FileHeader.NumberOfSections; i++, section++)
	{
		size_t endOfSection;
		if (section->SizeOfRawData == 0) {
			// Section without data in the DLL
			endOfSection = (size_t)section->VirtualAddress + optionalSectionSize;
		}
		else {
			endOfSection = (size_t)section->VirtualAddress + section->SizeOfRawData;
		}
		if (endOfSection > lastSectionEnd) {
			lastSectionEnd = endOfSection;
		}
	}
	// https://github.com/fancycode/MemoryModule/blob/master/MemoryModule.c#L613
	stubGetNativeSystemInfo(&SystemInfo);
	size_t alignedImageSize = AlignValueUp(_old_nt_hdr->OptionalHeader.SizeOfImage, SystemInfo.dwPageSize);
	if (alignedImageSize != AlignValueUp(lastSectionEnd, SystemInfo.dwPageSize)) {
		return -9;
	}

	/* ================================================================================
	* 2. Allocate memory for the DLL with VirtualAlloc with it's preferred base address
	=================================================================================*/

	DWORD _gle = 0;
	new_module_base = stubVirtualAlloc(
		(LPVOID)_old_nt_hdr->OptionalHeader.ImageBase,
		alignedImageSize,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE
	);

	if (!new_module_base) {
		new_module_base = stubVirtualAlloc(
			NULL,
			alignedImageSize,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE
		);
		if (!new_module_base) {
			return -10;
		}
	}


#ifdef _WIN64
	// https://github.com/fancycode/MemoryModule/blob/master/MemoryModule.c#L641

	/* ========================================================================
	* 3. Ensure that the allocated memory does not cross a 4GB boundary for x64
	======================================================================== */

	if (((uintptr_t)new_module_base >> 32) < (((uintptr_t)new_module_base + alignedImageSize) >> 32)) {
		// if it does, don't even bother trying again at this point
		stubVirtualFree(new_module_base, alignedImageSize, MEM_RELEASE);
		return -11;
	}

#endif

	/* ==================
	* 4. Copy the headers
	================== */

	// 4.1 commit memory for the headers
	// https://github.com/fancycode/MemoryModule/blob/master/MemoryModule.c#L697
	LPVOID lpNewHeaderAddr = stubVirtualAlloc(new_module_base, _old_nt_hdr->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE);

	// copy dos header
	for (size_t i = 0; i < _old_nt_hdr->OptionalHeader.SizeOfHeaders; i++) {
		((unsigned char*)lpNewHeaderAddr)[i] = ((unsigned char*)_old_dos_hdr)[i];
	}

	/* ================================================================
	* 5. Update the OptionalHeader.ImageBase to be the allocated buffer
	================================================================ */
	_new_dos_hdr = (IMAGE_DOS_HEADER*)lpNewHeaderAddr;
	_new_nt_hdr = (IMAGE_NT_HEADERS*)((uintptr_t)lpNewHeaderAddr + _new_dos_hdr->e_lfanew);
	_new_nt_hdr->OptionalHeader.ImageBase = (ULONGLONG)new_module_base;


	/* ========================================================
	* 6. Copy all of the sections to their respective addresses
	======================================================== */

	PIMAGE_SECTION_HEADER pSectionHdr = IMAGE_FIRST_SECTION(_new_nt_hdr);
	uintptr_t dest = 0;
	for (size_t i = 0; i < _new_nt_hdr->FileHeader.NumberOfSections; i++, pSectionHdr++) {
		if (pSectionHdr->SizeOfRawData == 0) {
			size_t section_size = _old_nt_hdr->OptionalHeader.SectionAlignment;
			if (section_size) {
				dest = (uintptr_t)stubVirtualAlloc(
					(LPVOID)((uintptr_t)new_module_base + pSectionHdr->VirtualAddress),
					section_size,
					MEM_COMMIT,
					PAGE_READWRITE
				);
				if (!dest) {
					return -12;
				}
				dest = (uintptr_t)new_module_base + pSectionHdr->VirtualAddress;
				pSectionHdr->Misc.PhysicalAddress = (DWORD)(dest & 0xffffffff);

				// Zero out the committed section
				__stosb((unsigned char*)dest, 0, section_size); // rather not use another for loop here.
			}
			continue;
		}

		dest = (uintptr_t)stubVirtualAlloc(
			(LPVOID)((uintptr_t)new_module_base + pSectionHdr->VirtualAddress),
			pSectionHdr->SizeOfRawData,
			MEM_COMMIT,
			PAGE_READWRITE
		);
		if (!dest) {
			return -13;
		}
		dest = (uintptr_t)new_module_base + pSectionHdr->VirtualAddress;
		const void* orig_dest = (const void*)(old_base_addr + pSectionHdr->PointerToRawData);
		// copy it over

		for (ULONG i = 0; i < pSectionHdr->SizeOfRawData; i++) {
			((PBYTE)dest)[i] = ((PBYTE)orig_dest)[i];
		}
		pSectionHdr->Misc.PhysicalAddress = (DWORD)(dest & 0xffffffff);
	}
	/* =========================================================================================================================
	* 7. If we did not allocate to the preferred image base(e.g.New->OptionalHeader.ImageBase != Old->OptionalHeader.ImageBase),
	*	 Perform relocations
	========================================================================================================================= */
	// TIL about ptrdiff_t
	if ((_new_nt_hdr->OptionalHeader.ImageBase - _old_nt_hdr->OptionalHeader.ImageBase) != 0) {
		/*==============
		RELOC PROCESSING
		==============*/
		// https://github.com/monoxgas/sRDI/blob/master/ShellcodeRDI/ShellcodeRDI.c#L354
		baseOffset = (uintptr_t)new_module_base - _new_nt_hdr->OptionalHeader.ImageBase;
		dataDir = _new_nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (dataDir.Size && baseOffset) {
			PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)((uintptr_t)new_module_base + dataDir.VirtualAddress);
			while (relocation->VirtualAddress) {
				PIMAGE_RELOC relocList = NULL;
				relocList = (PIMAGE_RELOC)(relocation + 1);
				while ((PBYTE)relocList != (PBYTE)relocation + relocation->SizeOfBlock) {
					if (relocList->type == IMAGE_REL_BASED_DIR64)
						*(PULONG_PTR)((PBYTE)(uintptr_t)new_module_base + relocation->VirtualAddress + relocList->offset) += baseOffset;
					else if (relocList->type == IMAGE_REL_BASED_HIGHLOW)
						*(PULONG_PTR)((PBYTE)(uintptr_t)new_module_base + relocation->VirtualAddress + relocList->offset) += (DWORD)baseOffset;
					else if (relocList->type == IMAGE_REL_BASED_HIGH)
						*(PULONG_PTR)((PBYTE)(uintptr_t)new_module_base + relocation->VirtualAddress + relocList->offset) += HIWORD(baseOffset);
					else if (relocList->type == IMAGE_REL_BASED_LOW)
						*(PULONG_PTR)((PBYTE)(uintptr_t)new_module_base + relocation->VirtualAddress + relocList->offset) += LOWORD(baseOffset);

					relocList++;
				}
				relocation = (PIMAGE_BASE_RELOCATION)relocList;
			}
		}
	}

	/* =============
	* 8. Process IAT
	============= */

	// Normal imports
	PIMAGE_IMPORT_DESCRIPTOR _import = (PIMAGE_IMPORT_DESCRIPTOR)(_new_nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (uintptr_t)new_module_base);
	if (_new_nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		while (_import->Name) {
			const char* importName = (const char*)((uintptr_t)new_module_base + _import->Name);

			HMODULE loadedModule = stubLoadLibraryA(importName);

			// Walk through all of the imports this dll has
			PIMAGE_THUNK_DATA pImgThunk = (PIMAGE_THUNK_DATA)(_import->FirstThunk + (uintptr_t)new_module_base);
			PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)(_import->OriginalFirstThunk + (uintptr_t)new_module_base);
			// for every import, calculate the actual RVA 

			while (pImgThunk->u1.Function != NULL) {
				if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal)) {
					stubLdrGetProcedureAddress(loadedModule, NULL, (WORD)pOriginalThunk->u1.Ordinal, (PVOID*)&(pImgThunk->u1.Function));
				}
				else {
					PIMAGE_IMPORT_BY_NAME pFname = (PIMAGE_IMPORT_BY_NAME)((uintptr_t)new_module_base + pOriginalThunk->u1.AddressOfData);
					pImgThunk->u1.Function = (ULONGLONG)stubGetProcAddress(loadedModule, pFname->Name);
				}

				pOriginalThunk++;
				pImgThunk++;
			}
			_import++;
		}
	}

	// Delayed imports
	// https://github.com/monoxgas/sRDI/blob/master/ShellcodeRDI/ShellcodeRDI.c#L432
	if (_new_nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size) {
		PIMAGE_DELAYLOAD_DESCRIPTOR _delayload = (PIMAGE_DELAYLOAD_DESCRIPTOR)(_new_nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress + (uintptr_t)new_module_base);
		while (_delayload->DllNameRVA) {
			const char* strDelayLib = (const char*)((uintptr_t)new_module_base + _delayload->DllNameRVA);
			HMODULE hDelayLib = stubLoadLibraryA(strDelayLib);
			PIMAGE_THUNK_DATA pImgThunk = (PIMAGE_THUNK_DATA)(_import->FirstThunk + (uintptr_t)new_module_base);
			PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)(_import->OriginalFirstThunk + (uintptr_t)new_module_base);
			while (pImgThunk->u1.Function != NULL) {
				if (IMAGE_SNAP_BY_ORDINAL(pImgThunk->u1.Ordinal)) {
					stubLdrGetProcedureAddress(hDelayLib, NULL, (WORD)pImgThunk->u1.Ordinal, &pImgThunk->u1.Function);
				}
				else {
					PANSI_STRING pAstrDelayFunctionName = NULL;
					stubRtlInitAnsiString(pAstrDelayFunctionName, (const char*)(pImgThunk->u1.AddressOfData + hDelayLib));
					stubLdrGetProcedureAddress(hDelayLib, pAstrDelayFunctionName, NULL, &pImgThunk->u1.Function);
				}
				PIMAGE_IMPORT_BY_NAME pFname = (PIMAGE_IMPORT_BY_NAME)((uintptr_t)new_module_base + pOriginalThunk->u1.AddressOfData);
				DWORD oldProtect = 0;
				pImgThunk->u1.Function = (ULONGLONG)stubGetProcAddress(hDelayLib, pFname->Name);
				pOriginalThunk++;
				pImgThunk++;
			}
			_delayload++;
		}
	}

	/* ==========================================
	* 9. Change each section's memory permissions
	========================================== */

	// https://github.com/monoxgas/sRDI/blob/master/ShellcodeRDI/ShellcodeRDI.c#L462
	section = IMAGE_FIRST_SECTION(_new_nt_hdr);
	DWORD executable = 0;
	DWORD readable = 0;
	DWORD writeable = 0;
	DWORD protect = 0;
	for (int i = 0; i < _new_nt_hdr->FileHeader.NumberOfSections; i++, section++) {

		if (section->SizeOfRawData) {

			// determine protection flags based on characteristics
			executable = (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
			readable = (section->Characteristics & IMAGE_SCN_MEM_READ) != 0;
			writeable = (section->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

			if (!executable && !readable && !writeable)
				protect = PAGE_NOACCESS;
			else if (!executable && !readable && writeable)
				protect = PAGE_WRITECOPY;
			else if (!executable && readable && !writeable)
				protect = PAGE_READONLY;
			else if (!executable && readable && writeable)
				protect = PAGE_READWRITE;
			else if (executable && !readable && !writeable)
				protect = PAGE_EXECUTE;
			else if (executable && !readable && writeable)
				protect = PAGE_EXECUTE_WRITECOPY;
			else if (executable && readable && !writeable)
				protect = PAGE_EXECUTE_READ;
			else if (executable && readable && writeable)
				protect = PAGE_EXECUTE_READWRITE;

			if (section->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
				protect |= PAGE_NOCACHE;
			}

			// change memory access flags
			stubVirtualProtect(
				(LPVOID)((uintptr_t)new_module_base + section->VirtualAddress),
				section->SizeOfRawData,
				protect, &protect
			);
		}

	}

	stubFlushInstructionCache((HANDLE)-1, NULL, 0);
	/*
	======================================================
	EXCEPTION PROCESSING
	======================================================
	*/
#ifdef _WIN64
	// https://github.com/monoxgas/sRDI/blob/master/ShellcodeRDI/ShellcodeRDI.c#L530 
	// forgot to make sure the size AND data exist
	dataDir = _new_nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	
	if (dataDir.Size && stubRtlAddFunctionTable) {
		//https://reactos.org/wiki/Techwiki:SEH64
		PIMAGE_RUNTIME_FUNCTION_ENTRY pData = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(_new_nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress + (uintptr_t)new_module_base);
		stubRtlAddFunctionTable(pData, (dataDir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) - 1, (uintptr_t)new_module_base);
	}
#endif 


	/*
	======================================================
	TLS PROCESSING
	======================================================
	*/
	if (_new_nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {

		PIMAGE_TLS_DIRECTORY pTlsDirectory = (PIMAGE_TLS_DIRECTORY)(_new_nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress + (uintptr_t)new_module_base);

		// SHAMELESSLY stolen from https://github.com/monoxgas/sRDI/blob/7889036a75e3aca65a2c01ee8f5549ed779a4c1f/ShellcodeRDI/ShellcodeRDI.c#L518
		PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)(pTlsDirectory->AddressOfCallBacks);

		for (; *callback; callback++) {
			(*callback)((LPVOID)new_module_base, DLL_PROCESS_ATTACH, NULL);
		}
	}

	uintptr_t entrypoint = _new_nt_hdr->OptionalHeader.AddressOfEntryPoint + (uintptr_t)new_module_base;
	pDllMain stubDllMain = (pDllMain)(entrypoint);
	stubDllMain((HINSTANCE)new_module_base, DLL_PROCESS_ATTACH, NULL);
	return (uintptr_t)new_module_base;
}
// END LOADER FUNCTION