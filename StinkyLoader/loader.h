/*
	TODOS:
		1. Check allocations with NtAllocateVirtualMemory, ensure size allocated >= size required
		2. Remove duplicate vars
*/


#pragma once
#include <Windows.h>
#include <winnt.h>
#include <winternl.h>
#include "PebLdrInline.h"

#ifdef _LOADER_DEBUG
#include <stdio.h>
#endif

#define MAXIMUM_HEADER_SEARCH_BYTES 0x3000

#define ERROR_HDR_NOT_FOUND -1
#define ERROR_LOADER_INIT_FAILED -2

typedef BOOL(WINAPI* pFlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);
typedef BOOL(WINAPI* pDllMain)(HINSTANCE, DWORD, LPVOID);

// ntdll
typedef VOID(WINAPI* pRtlFreeUnicodeString)(PUNICODE_STRING);
typedef NTSTATUS(WINAPI* pLdrLoadDll)(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);
typedef NTSTATUS(WINAPI* pRtlAnsiStringToUnicodeString)(PUNICODE_STRING, PCANSI_STRING, BOOLEAN);
typedef NTSTATUS(WINAPI* pNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(WINAPI* pNtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS(WINAPI* pNtAllocateVirtualMemory)(HANDLE, PVOID, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef VOID(WINAPI* pRtlInitAnsiString)(PANSI_STRING, PCSZ);
typedef NTSTATUS(WINAPI* pLdrGetProcedureAddress)(HMODULE, PANSI_STRING, WORD, PVOID);
#ifdef _WIN64
typedef BOOL(WINAPI* pRtlAddFunctionTable)(PRUNTIME_FUNCTION, DWORD, DWORD64);
#endif

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
#pragma intrinsic(strlen)
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
		return ERROR_HDR_NOT_FOUND;
	}

	// begin initialize loader data
	uintptr_t k32base = (uintptr_t)getK32();
	uintptr_t ntbase = (uintptr_t)getNtdll();

	LDR_DATA ldrKernel32 = { 0 };
	LDR_DATA ldrNtdll = { 0 };

	if (!init_ldr_data(&ldrKernel32, (HMODULE)k32base)) {
		return ERROR_LOADER_INIT_FAILED;
	}

	if (!init_ldr_data(&ldrNtdll, (HMODULE)ntbase)) {
		return ERROR_LOADER_INIT_FAILED;
	}
	// end initialize loader data

	UNICODE_STRING UnicodeString = { 0 };
	ANSI_STRING astrFunc = { 0 };
	SYSTEM_BASIC_INFORMATION sbi = { 0 };
	pcall_rel32 pc32 = { 0 };
	plea_rel32 pl32 = { 0 };
	PIMAGE_SECTION_HEADER section = NULL;
	uintptr_t address_of_entry = 0;
	LPVOID new_module_base = NULL;
	uintptr_t baseOffset = 0;
	SIZE_T szAllocation = 0;
	SIZE_T szAllocationBase = 0;
	NTSTATUS status = 0;
	HANDLE hCurrentProcess = (HANDLE)-1;
	IMAGE_DATA_DIRECTORY dataDir;
	PVOID pPattern = 0;
	PPEB ppeb = NULL;
	PLIST_ENTRY pLdrpHashTable = 0;
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

	// kernel32 hashes
	constexpr DWORD cdwFlushInstructionCache = cexpr_adler32("FlushInstructionCache");

	// k32 stubs
	pFlushInstructionCache stubFlushInstructionCache = NULL;

	// ntdll hashes
	constexpr DWORD cdwNtQuerySystemInformation = cexpr_adler32("NtQuerySystemInformation");
	constexpr DWORD cdwRtlInitAnsiString = cexpr_adler32("RtlInitAnsiString");
	constexpr DWORD cdwLdrGetProcedureAddress = cexpr_adler32("LdrGetProcedureAddress");
	constexpr DWORD cdwNtAllocateVirtualMemory = cexpr_adler32("NtAllocateVirtualMemory");
	constexpr DWORD cdwNtFreeVirtualMemory = cexpr_adler32("NtFreeVirtualMemory");
	constexpr DWORD cdwNtProtectVirtualMemory = cexpr_adler32("NtProtectVirtualMemory");
	constexpr DWORD cdwLdrGetDllHandleByName = cexpr_adler32("LdrGetDllHandleByName");
	constexpr DWORD cdwLdrLoadDll = cexpr_adler32("LdrLoadDll");
	constexpr DWORD cdwRtlAnsiStringToUnicodeString = cexpr_adler32("RtlAnsiStringToUnicodeString");
	constexpr DWORD cdwRtlFreeUnicodeString = cexpr_adler32("RtlFreeUnicodeString");
#ifdef _WIN64
	constexpr DWORD cdwRtlAddFunctionTable = cexpr_adler32("RtlAddFunctionTable");
#endif

	//ntdll stubs
	PVOID pLdrGetDllHandleByName = NULL;
	pLdrLoadDll stubLdrLoadDll = NULL;
	pNtQuerySystemInformation stubNtQuerySystemInformation = NULL;
	pNtProtectVirtualMemory stubNtProtectVirtualMemory = NULL;
	pNtAllocateVirtualMemory stubNtAllocateVirtualMemory = NULL;
	pNtFreeVirtualMemory stubNtFreeVirtualMemory = NULL;
	pRtlInitAnsiString stubRtlInitAnsiString = NULL;
	pLdrGetProcedureAddress stubLdrGetProcedureAddress = NULL;
	pRtlAnsiStringToUnicodeString stubRtlAnsiStringToUnicodeString = NULL;
	pRtlFreeUnicodeString stubRtlFreeUnicodeString = NULL;
#ifdef _WIN64
	pRtlAddFunctionTable stubRtlAddFunctionTable = NULL;
#endif

	/*
	======================================================
	IMPORTING NEEDED FUNCTIONS FROM K32
	======================================================
	*/


	stubFlushInstructionCache = (pFlushInstructionCache)get_from_ldr_data(&ldrKernel32, cdwFlushInstructionCache);
	if (!stubFlushInstructionCache)
		return -43;

	/*
	======================================================
	IMPORTING NEEDED FUNCTIONS FROM NTDLL
	======================================================
	*/

	
	stubNtProtectVirtualMemory = (pNtProtectVirtualMemory)get_from_ldr_data(&ldrNtdll, cdwNtProtectVirtualMemory);
	if (!stubNtProtectVirtualMemory)
		return -42;
	
	stubNtQuerySystemInformation = (pNtQuerySystemInformation)get_from_ldr_data(&ldrNtdll, cdwNtQuerySystemInformation);
	if (!stubNtQuerySystemInformation)
		return -44;

	stubNtFreeVirtualMemory = (pNtFreeVirtualMemory)get_from_ldr_data(&ldrNtdll, cdwNtFreeVirtualMemory);
	if (!stubNtFreeVirtualMemory)
		return -45;

	stubNtAllocateVirtualMemory = (pNtAllocateVirtualMemory)get_from_ldr_data(&ldrNtdll, cdwNtAllocateVirtualMemory);
	if (!stubNtAllocateVirtualMemory)
		return -46;

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

	pLdrGetDllHandleByName = get_from_ldr_data(&ldrNtdll, cdwLdrGetDllHandleByName);
	if (!pLdrGetDllHandleByName)
		return -51;

	stubLdrLoadDll = (pLdrLoadDll)get_from_ldr_data(&ldrNtdll, cdwLdrLoadDll);
	if (!stubLdrLoadDll)
		return -52;

	stubRtlAnsiStringToUnicodeString = (pRtlAnsiStringToUnicodeString)get_from_ldr_data(&ldrNtdll, cdwRtlAnsiStringToUnicodeString);
	if (!stubRtlAnsiStringToUnicodeString)
		return -53;

	stubRtlFreeUnicodeString = (pRtlFreeUnicodeString)get_from_ldr_data(&ldrNtdll, cdwRtlFreeUnicodeString);
	if (!stubRtlFreeUnicodeString)
		return -54;


	/* =================================================================================
	*  0. Set up everything needed for the LdrpHashTable searching
	================================================================================= */
	pPattern = findPattern(pLdrGetDllHandleByName, prelude1, sizeof(prelude1));
	if (pPattern) {
		pc32 = (pcall_rel32)((PBYTE)pPattern + sizeof(prelude1));
		PBYTE pLdrpFindLoadedDllByName = (PBYTE)pPattern + sizeof(prelude1) + pc32->offset + sizeof(call_rel32);
		pPattern = findPattern(pLdrpFindLoadedDllByName, prelude2, sizeof(prelude2));
		if (pPattern) {
			pcall_rel32 pcall_LdrpFindLoadedDllByNameLockHeld = (pcall_rel32)((PBYTE)pPattern + sizeof(prelude2));
			PVOID pLdrpFindLoadedDllByNameLockHeld = (PBYTE)pPattern + sizeof(prelude2) + pcall_LdrpFindLoadedDllByNameLockHeld->offset + sizeof(call_rel32);
			// now find the hash table
			pPattern = findPattern(pLdrpFindLoadedDllByNameLockHeld, prelude3, sizeof(prelude3));
			plea_rel32 plea_LdrpHashTable = (plea_rel32)((PBYTE)pPattern + sizeof(prelude3));
			pLdrpHashTable = (PLIST_ENTRY)((PBYTE)pPattern + sizeof(prelude3) + plea_LdrpHashTable->offset + sizeof(lea_rel32));
		}
	}

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
	ULONG ulBytesRead = 0;
	DWORD dwPageSize = 0;

	status = stubNtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(SYSTEM_BASIC_INFORMATION), &ulBytesRead);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	dwPageSize = *(DWORD*)(sbi.Reserved1 + 2);
	size_t alignedImageSize = AlignValueUp(_old_nt_hdr->OptionalHeader.SizeOfImage, dwPageSize);
	if (alignedImageSize != AlignValueUp(lastSectionEnd, dwPageSize)) {
		return -9;
	}

	/* ================================================================================
	* 2. Allocate memory for the DLL with VirtualAlloc with it's preferred base address
	=================================================================================*/
	new_module_base = (PVOID)_old_nt_hdr->OptionalHeader.ImageBase;
	szAllocation = alignedImageSize;

	status = stubNtAllocateVirtualMemory(
		hCurrentProcess,
		&new_module_base,
		NULL,
		&szAllocation,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE
	);

	if (!NT_SUCCESS(status)) {
		new_module_base = 0;
		status = stubNtAllocateVirtualMemory(
			hCurrentProcess,
			&new_module_base,
			NULL,
			&szAllocation,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE
		);
		if (!NT_SUCCESS(status)) {
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
		status = stubNtFreeVirtualMemory(hCurrentProcess, &new_module_base, &alignedImageSize, MEM_RELEASE);
		return -11;
	}

#endif

	/* ==================
	* 4. Copy the headers
	================== */

	// 4.1 commit memory for the headers
	// https://github.com/fancycode/MemoryModule/blob/master/MemoryModule.c#L697

	szAllocation = _old_nt_hdr->OptionalHeader.SizeOfHeaders;
	status = stubNtAllocateVirtualMemory(
		hCurrentProcess,
		&new_module_base,
		NULL,
		&szAllocation,
		MEM_COMMIT,
		PAGE_READWRITE
	);

	// copy dos header
	for (size_t i = 0; i < _old_nt_hdr->OptionalHeader.SizeOfHeaders; i++) {
		((unsigned char*)new_module_base)[i] = ((unsigned char*)_old_dos_hdr)[i];
	}

	/* ================================================================
	* 5. Update the OptionalHeader.ImageBase to be the allocated buffer
	================================================================ */
	_new_dos_hdr = (IMAGE_DOS_HEADER*)new_module_base;
	_new_nt_hdr = (IMAGE_NT_HEADERS*)((uintptr_t)new_module_base + _new_dos_hdr->e_lfanew);
	_new_nt_hdr->OptionalHeader.ImageBase = (ULONGLONG)new_module_base;


	/* ========================================================
	* 6. Copy all of the sections to their respective addresses
	======================================================== */

	PIMAGE_SECTION_HEADER pSectionHdr = IMAGE_FIRST_SECTION(_new_nt_hdr);
	uintptr_t dest = 0;
	for (size_t i = 0; i < _new_nt_hdr->FileHeader.NumberOfSections; i++, pSectionHdr++) {
		if (pSectionHdr->SizeOfRawData == 0) {
			size_t section_size = _old_nt_hdr->OptionalHeader.SectionAlignment; // opt
			
			szAllocation = section_size;
			szAllocationBase = ((uintptr_t)new_module_base + pSectionHdr->VirtualAddress);
			
			if (section_size) {
				status = stubNtAllocateVirtualMemory(
					hCurrentProcess,
					&szAllocationBase,
					NULL,
					&szAllocation,
					MEM_COMMIT,
					PAGE_READWRITE
				);
				if (!NT_SUCCESS(status)) {
					return -12;
				}
				dest = (uintptr_t)new_module_base + pSectionHdr->VirtualAddress;
				pSectionHdr->Misc.PhysicalAddress = (DWORD)(dest & 0xffffffff);

				// Zero out the committed section
				__stosb((unsigned char*)dest, 0, section_size); // rather not use another for loop here.
			}
			continue;
		}

		szAllocationBase = ((uintptr_t)new_module_base + pSectionHdr->VirtualAddress);
		szAllocation = pSectionHdr->SizeOfRawData;
		status = stubNtAllocateVirtualMemory(
			hCurrentProcess,
			&szAllocationBase,
			NULL,
			&szAllocation,
			MEM_COMMIT,
			PAGE_READWRITE
		);


		if (!NT_SUCCESS(status)) {
			return -13;
		}

		const void* orig_dest = (const void*)(old_base_addr + pSectionHdr->PointerToRawData);
		// copy it over

		for (ULONG i = 0; i < pSectionHdr->SizeOfRawData; i++) {
			((PBYTE)szAllocationBase)[i] = ((PBYTE)orig_dest)[i];
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
	if (!NT_SUCCESS(status))
		return -42069;

	// Normal imports
	PIMAGE_IMPORT_DESCRIPTOR _import = (PIMAGE_IMPORT_DESCRIPTOR)(_new_nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (uintptr_t)new_module_base);
	if (_new_nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		while (_import->Name) {
			const char* importName = (const char*)((uintptr_t)new_module_base + _import->Name);
			HMODULE loadedModule = 0;
			MODULEHASH mhModuleHash = static_x65599(importName);
			// check to see if the module is already loaded by 
			// walking the LdrpHashTable
			if (pLdrpHashTable)
			{
				ULONG ulHashTableOffset = mhModuleHash & 0x1f;		
				PVOID pHashTableData = pLdrpHashTable[ulHashTableOffset].Flink;
				if (pHashTableData != *(PVOID*)pHashTableData) {
					PLDR_DATA_TABLE_ENTRY pLdrDteModule = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pHashTableData - 0x70);
					loadedModule = (HMODULE)pLdrDteModule->DllBase;
				}
			}

			if(!loadedModule) {
				stubRtlInitAnsiString(&astrFunc, (PCSZ)importName);
				stubRtlAnsiStringToUnicodeString(&UnicodeString, &astrFunc, TRUE);
				status = stubLdrLoadDll(NULL, NULL, &UnicodeString, (PHANDLE)&loadedModule);
				stubRtlFreeUnicodeString(&UnicodeString);
				if (!NT_SUCCESS(status)) {
#ifdef _LOADER_DEBUG
					printf("LdrLoadDll Failed - 0x%x\n", status);
#endif
					return status;
				}

			}

#ifdef _LOADER_DEBUG
			printf("%s - %p\n", importName, loadedModule);
#endif
			

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
					stubRtlInitAnsiString(&astrFunc, pFname->Name);
					status = stubLdrGetProcedureAddress(loadedModule, &astrFunc, NULL, &(pImgThunk->u1.Function));
					if (!NT_SUCCESS(status)) {
#ifdef _LOADER_DEBUG
						printf("Failed to load from %s - %p\n", importName, loadedModule);
#endif
						return status;
					}
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
			HMODULE hDelayLib = NULL;
			stubRtlInitAnsiString(&astrFunc, (PCSZ)strDelayLib);
			stubRtlAnsiStringToUnicodeString(&UnicodeString, &astrFunc, TRUE);
			status = stubLdrLoadDll(NULL, NULL, &UnicodeString, (PHANDLE)&hDelayLib);
			stubRtlFreeUnicodeString(&UnicodeString);
			if (!NT_SUCCESS(status)) {
#ifdef _LOADER_DEBUG
				printf("Delayed Imports LdrLoadDll Failed - 0x%x\n", status);
#endif
				return status;
			}
			PIMAGE_THUNK_DATA pImgThunk = (PIMAGE_THUNK_DATA)(_import->FirstThunk + (uintptr_t)new_module_base);
			PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)(_import->OriginalFirstThunk + (uintptr_t)new_module_base);
			while (pImgThunk->u1.Function != NULL) {
				if (IMAGE_SNAP_BY_ORDINAL(pImgThunk->u1.Ordinal)) {
					stubLdrGetProcedureAddress(hDelayLib, NULL, (WORD)pImgThunk->u1.Ordinal, &pImgThunk->u1.Function);
				}
				else {
					stubRtlInitAnsiString(&astrFunc, (const char*)(pImgThunk->u1.AddressOfData + hDelayLib));
					stubLdrGetProcedureAddress(hDelayLib, &astrFunc, NULL, &pImgThunk->u1.Function);
				}
				PIMAGE_IMPORT_BY_NAME pFname = (PIMAGE_IMPORT_BY_NAME)((uintptr_t)new_module_base + pOriginalThunk->u1.AddressOfData);
				DWORD oldProtect = 0;
				stubRtlInitAnsiString(&astrFunc, pFname->Name);
				//pImgThunk->u1.Function = (ULONGLONG)stubGetProcAddress(hDelayLib, pFname->Name);
				status = stubLdrGetProcedureAddress(hDelayLib, &astrFunc, NULL, &(pImgThunk->u1.Function));
				if (!status) {
					return status;
				}
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

			PVOID lpBase = (PVOID)((uintptr_t)new_module_base + section->VirtualAddress);
			SIZE_T ulAllocationSize = section->SizeOfRawData;
			status = stubNtProtectVirtualMemory(
				hCurrentProcess, 
				&lpBase, 
				&ulAllocationSize, 
				protect, 
				&protect
			);
			if (!NT_SUCCESS(status)) {
				return status;
			}
		}

	}

	stubFlushInstructionCache(hCurrentProcess, NULL, 0);
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
	
	// zero DOS and NT headers
	__stosb((unsigned char*)_new_dos_hdr, 0, sizeof(IMAGE_DOS_HEADER));
	__stosb((unsigned char*)_new_nt_hdr, 0, sizeof(IMAGE_NT_HEADERS));

	stubDllMain((HINSTANCE)new_module_base, DLL_PROCESS_ATTACH, NULL);
	return (uintptr_t)new_module_base;
}
// END LOADER FUNCTION